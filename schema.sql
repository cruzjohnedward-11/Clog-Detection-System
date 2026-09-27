CREATE DATABASE IF NOT EXISTS clogdetection
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE clogdetection;

CREATE TABLE IF NOT EXISTS account_request (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    requester_name VARCHAR(150) NOT NULL,
    requester_role VARCHAR(100) NOT NULL,
    requester_contact VARCHAR(40) NULL,
    requested_name VARCHAR(150) NULL,
    requested_role VARCHAR(100) NULL,
    requested_contact VARCHAR(40) NULL,
    requested_email VARCHAR(254) NULL,
    change_reason TEXT NULL,
    password_reset_requested BOOLEAN NOT NULL DEFAULT FALSE,
    status ENUM('pending', 'approved', 'rejected') NOT NULL DEFAULT 'pending',
    submitted_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    INDEX idx_account_request_status_submitted (status, submitted_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;