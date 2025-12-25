package store

import (
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/goodieshq/sceptune/pkg/utils"
	"github.com/rs/zerolog/log"
	_ "modernc.org/sqlite"
)

type CertificateStore struct {
	db *sql.DB
}

type CertificateRecord struct {
	ID                        string
	TransactionID             string
	CertificateSigningRequest string
	Certificate               string
	Expiration                time.Time
	IntuneNotified            bool
}

func createTables(db *sql.DB) error {
	_, err := db.Exec(`
	CREATE TABLE IF NOT EXISTS certificates (
	 	id TEXT PRIMARY KEY,
		transaction_id TEXT NOT NULL,
		certificate_signing_request TEXT NOT NULL,
		certificate TEXT NOT NULL,
		expiration TIMESTAMP NOT NULL,
		intune_notified BOOLEAN NOT NULL DEFAULT FALSE
	);

	CREATE INDEX IF NOT EXISTS idx_expiration ON certificates(expiration);
	CREATE INDEX IF NOT EXISTS idx_intune_notified ON certificates(intune_notified) WHERE intune_notified = FALSE;
	`)
	return err
}

func NewCertificateStore(path string) (*CertificateStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to enable WAL mode: %w", err)
	}
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(1 * time.Hour)

	if err := createTables(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to create tables: %w", err)
	}

	return &CertificateStore{
		db: db,
	}, nil
}

func (cs *CertificateStore) StoreCert(csr, txid string, crt *x509.Certificate) error {
	if crt == nil || len(crt.Raw) == 0 {
		return fmt.Errorf("certificate is empty")
	}

	id := utils.CreateDBID(csr, txid)

	_, err := cs.db.Exec(`
		INSERT OR REPLACE INTO certificates (
			id, transaction_id, certificate_signing_request, certificate, expiration, intune_notified
		) VALUES (
		 ?, ?, ?, ?, ?, ?
		)
	`, id, txid, csr, base64.StdEncoding.EncodeToString(crt.Raw), crt.NotAfter, false)
	return err
}

func (cs *CertificateStore) GetCert(csr, txid string) (*x509.Certificate, bool, error) {
	id := utils.CreateDBID(csr, txid)

	var certRecord CertificateRecord

	err := cs.db.QueryRow(`
		SELECT
			id, transaction_id, certificate_signing_request, certificate, expiration, intune_notified
		FROM
			certificates
		WHERE id = ?
	`, id).Scan(
		&certRecord.ID,
		&certRecord.TransactionID,
		&certRecord.CertificateSigningRequest,
		&certRecord.Certificate,
		&certRecord.Expiration,
		&certRecord.IntuneNotified,
	)

	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}

	if err != nil {
		return nil, false, err
	}

	certBytes, err := base64.StdEncoding.DecodeString(certRecord.Certificate)
	if err != nil {
		return nil, false, fmt.Errorf("failed to decode certificate from base64: %w", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, false, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, certRecord.IntuneNotified, nil
}

func (cs *CertificateStore) MarkIntuneNotified(csr, txid string) (bool, error) {
	dbid := utils.CreateDBID(csr, txid)

	result, err := cs.db.Exec(`
		UPDATE certificates
		SET intune_notified = TRUE
		WHERE id = ?
	`, dbid)
	if err != nil {
		return false, err
	}

	count, err := result.RowsAffected()
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (cs *CertificateStore) GetPendingNotifications(limit int) ([]CertificateRecord, error) {
	rows, err := cs.db.Query(`
		SELECT
			id, transaction_id, certificate_signing_request, certificate, expiration, intune_notified
		FROM certificates
		WHERE intune_notified = FALSE
		ORDER BY expiration ASC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []CertificateRecord
	for rows.Next() {
		var r CertificateRecord
		if err := rows.Scan(&r.ID, &r.TransactionID, &r.CertificateSigningRequest, &r.Certificate, &r.Expiration, &r.IntuneNotified); err != nil {
			return nil, err
		}
		records = append(records, r)
	}

	return records, rows.Err()
}

func (cs *CertificateStore) PurgeExpired() (int64, error) {
	// Calculate the cutoff timestamp (expired > 24 hours ago)
	timestamp := time.Now()
	timestamp = timestamp.Add(-24 * time.Hour)

	result, err := cs.db.Exec(`
		DELETE FROM certificates
		WHERE expiration < ?
	`, timestamp)

	if err != nil {
		return 0, err
	}

	count, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}

	// check number of rows affected
	if count == 0 {
		log.Debug().Msg("No expired certificates found to purge")
	} else {
		log.Info().Int64("count", count).Msg("Purged expired certificates")
	}

	return count, nil
}

func (cs *CertificateStore) Close() error {
	return cs.db.Close()
}
