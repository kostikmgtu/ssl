package ssl

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// SMBConfig содержит параметры подключения к файловому серверу Windows
type SMBConfig struct {
	Server      string // DNS-имя или IP
	Port        int    // Обычно 445
	Share       string // Имя сетевой папки
	Username    string
	Password    string
	Domain      string // Домен AD или пустая строка
	SertCatalog string // Путь к сертификатам на SMB-шаре
}

// CertManager обеспечивает потокобезопасное хранение и динамическую подмену TLS-сертификата
type CertManager struct {
	cert atomic.Pointer[tls.Certificate]
}

// StartWebServer запускает HTTPS-сервер с переданным обработчиком handler (роутером)
func StartWebServer(addrint int, handler http.Handler, smbCfg SMBConfig) error {

	addr := fmt.Sprintf(":%d", addrint)
	certMgr := &CertManager{}
	certReady := make(chan struct{})

	go certMgr.startCertReloader(smbCfg, certReady)

	log.Println("[HTTPServer] Ожидание готовности TLS-сертификата...")
	<-certReady

	server := &http.Server{
		Addr:    addr,
		Handler: handler,
		TLSConfig: &tls.Config{
			GetCertificate: certMgr.GetCertificate,
			MinVersion:     tls.VersionTLS12,
		},
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("[HTTPServer] Слушатель открыт: https://localhost%s\n", addr)
	return server.ListenAndServeTLS("", "")
}

// GetCertificate реализует колбэк tls.Config.GetCertificate
func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cert := cm.cert.Load()
	if cert == nil {
		return nil, fmt.Errorf("TLS-сертификат еще не инициализирован")
	}
	return cert, nil
}

// readRemoteFile считывает файл с SMB-шары в срез байт
func readRemoteFile(fs *smb2.RemoteFileSystem, filename string) ([]byte, error) {
	file, err := fs.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return io.ReadAll(file)
}

// fetchCertificatesDirectly подключается к SMB-серверу, читает файлы и собирает пару ключей в памяти
func (cm *CertManager) fetchCertificatesDirectly(cfg SMBConfig) error {
	addr := fmt.Sprintf("%s:%d", cfg.Server, cfg.Port)
	dialer := net.Dialer{Timeout: 10 * time.Second}

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("ошибка сетевого подключения к %s: %w", addr, err)
	}
	defer conn.Close()

	initiator := &smb2.NTLMInitiator{
		User:     cfg.Username,
		Password: cfg.Password,
		Domain:   cfg.Domain,
	}

	d := &smb2.Dialer{Initiator: initiator}
	session, err := d.Dial(conn)
	if err != nil {
		return fmt.Errorf("ошибка NTLM-аутентификации на %s: %w", addr, err)
	}
	defer session.Logoff()

	fs, err := session.Mount(cfg.Share)
	if err != nil {
		return fmt.Errorf("не удалось открыть шару \\\\%s\\%s: %w", cfg.Server, cfg.Share, err)
	}
	defer fs.Umount()

	certBytes, err := readRemoteFile(fs, cfg.SertCatalog+`\fullchain.pem`)
	if err != nil {
		log.Printf("[CertManager] fullchain.pem не найден, попытка прочитать cert.pem: %v", err)
		certBytes, err = readRemoteFile(fs, cfg.SertCatalog+`\cert.pem`)
		if err != nil {
			return fmt.Errorf("не удалось прочитать ни fullchain.pem, ни cert.pem: %w", err)
		}
	}

	keyBytes, err := readRemoteFile(fs, cfg.SertCatalog+`\privkey.pem`)
	if err != nil {
		return fmt.Errorf("ошибка чтения privkey.pem: %w", err)
	}

	newCert, err := tls.X509KeyPair(certBytes, keyBytes)
	if err != nil {
		return fmt.Errorf("ошибка разбора пары TLS X.509: %w", err)
	}

	cm.cert.Store(&newCert)
	log.Printf("[CertManager] TLS-сертификат успешно загружен из \\\\%s\\%s", cfg.Server, cfg.Share)
	return nil
}

// startCertReloader выполняет первичную загрузку и запускает фоновое обновление раз в 24 часа
func (cm *CertManager) startCertReloader(cfg SMBConfig, certReady chan<- struct{}) {
	log.Println("[CertManager] Первичная загрузка сертификата по SMB...")

	// Первичная загрузка сертификата
	for {
		if err := cm.fetchCertificatesDirectly(cfg); err != nil {
			log.Printf("[CertManager] Ошибка загрузки сертификата: %v. Повтор через 10 секунд...", err)
			time.Sleep(10 * time.Second)
			continue
		}

		close(certReady)
		break
	}

	go func() {
		for {
			now := time.Now()

			// Вычисляем ближайшее время обновления — 00:01:00
			nextUpdate := time.Date(
				now.Year(),
				now.Month(),
				now.Day(),
				0, 1, 0, 0,
				now.Location(),
			)

			// Если сегодня 00:01 уже прошло, назначаем на завтра
			if !now.Before(nextUpdate) {
				nextUpdate = nextUpdate.AddDate(0, 0, 1)
			}

			delay := time.Until(nextUpdate)

			log.Printf("[CertManager] Следующее плановое обновление сертификата: %s (через %s)",
				nextUpdate.Format("2006-01-02 15:04:05"),
				delay.Round(time.Second),
			)

			timer := time.NewTimer(delay)
			<-timer.C

			log.Println("[CertManager] Начало планового обновления сертификата...")

			if err := cm.fetchCertificatesDirectly(cfg); err != nil {
				log.Printf("[CertManager] Ошибка планового обновления: %v", err)
			}
		}
	}()
}
