// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package snowflake

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
	"sync"
	"time"

	"github.com/hashicorp/errwrap"
	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/vault/sdk/database/helper/dbutil"

	"github.com/hashicorp/vault/sdk/database/helper/connutil"
	"github.com/mitchellh/mapstructure"
	"github.com/snowflakedb/gosnowflake"
)

var (
	ErrInvalidSnowflakeURL           = fmt.Errorf("invalid connection URL format, expect <account_name>.snowflakecomputing.com/<db_name>")
	ErrInvalidPrivateKey             = fmt.Errorf("failed to read provided private_key")
	accountAndDBNameFromConnURLRegex = regexp.MustCompile(`^(.+)\.snowflakecomputing\.com/(.+)$`) // Expected format: <account_name>.snowflakecomputing.com/<db_name>
)

type snowflakeConnectionProducer struct {
	ConnectionURL            string      `json:"connection_url"`
	MaxOpenConnections       int         `json:"max_open_connections"`
	MaxIdleConnections       int         `json:"max_idle_connections"`
	MaxConnectionLifetimeRaw interface{} `json:"max_connection_lifetime"`
	Username                 string      `json:"username"`
	Password                 string      `json:"password"`
	PrivateKey               []byte      `json:"private_key"`
	UsernameTemplate         string      `json:"username_template"`
	DisableEscaping          bool        `json:"disable_escaping"`

	Initialized           bool
	RawConfig             map[string]any
	Type                  string
	maxConnectionLifetime time.Duration
	logger                log.Logger
	snowflakeDB           *sql.DB
	mu                    sync.RWMutex
}

func (c *snowflakeConnectionProducer) secretValues() map[string]string {
	return map[string]string{
		c.Password:           "[password]",
		string(c.PrivateKey): "[private_key]",
	}
}

func (c *snowflakeConnectionProducer) Init(ctx context.Context, initConfig map[string]interface{}, verifyConnection bool) (saveConfig map[string]interface{}, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.RawConfig = initConfig

	c.logger = log.New(&log.LoggerOptions{})

	decoderConfig := &mapstructure.DecoderConfig{
		Result:           c,
		WeaklyTypedInput: true,
		TagName:          "json",
	}

	decoder, err := mapstructure.NewDecoder(decoderConfig)
	if err != nil {
		return nil, err
	}

	err = decoder.Decode(initConfig)
	if err != nil {
		return nil, err
	}

	if len(c.ConnectionURL) == 0 {
		return nil, fmt.Errorf("connection_url cannot be empty")
	}

	if len(c.Password) > 0 {
		// Return an error here once Snowflake ends support for password auth.
		c.logger.Warn("[DEPRECATED] Single-factor password authentication is deprecated in Snowflake and will be removed by November 2025. " +
			"Key pair authentication will be required after this date.")

		username := c.Username
		password := c.Password

		if !c.DisableEscaping {
			username = url.PathEscape(c.Username)
			password = url.PathEscape(c.Password)
		}

		// Replace templated username and password in connection URL with actual values
		c.ConnectionURL = dbutil.QueryHelper(c.ConnectionURL, map[string]string{
			"username": username,
			"password": password,
		})
	}

	if len(c.PrivateKey) > 0 {

		username := c.Username
		privateKey := c.PrivateKey

		if !c.DisableEscaping {
			username = url.PathEscape(c.Username)
		}

		// Replace templated username and privateKey in connection URL with actual values
		c.ConnectionURL = dbutil.QueryHelper(c.ConnectionURL, map[string]string{
			"username":   username,
			"privateKey": base64.StdEncoding.EncodeToString(privateKey),
		})
	}

	if c.MaxOpenConnections == 0 {
		c.MaxOpenConnections = 4
	}

	if c.MaxIdleConnections == 0 {
		c.MaxIdleConnections = c.MaxOpenConnections
	}
	if c.MaxIdleConnections > c.MaxOpenConnections {
		c.MaxIdleConnections = c.MaxOpenConnections
	}
	if c.MaxConnectionLifetimeRaw == nil {
		c.MaxConnectionLifetimeRaw = "0s"
	}

	c.maxConnectionLifetime, err = parseutil.ParseDurationSecond(c.MaxConnectionLifetimeRaw)
	if err != nil {
		return nil, errwrap.Wrapf("invalid max_connection_lifetime: {{err}}", err)
	}

	c.Initialized = true

	if verifyConnection {
		if _, err := c.Connection(ctx); err != nil {
			c.close()
			return nil, fmt.Errorf("error verifying connection: %w", err)
		}
	}

	return initConfig, nil
}

func (c *snowflakeConnectionProducer) Initialize(ctx context.Context, config map[string]any, verifyConnection bool) error {
	_, err := c.Init(ctx, config, verifyConnection)
	return err
}

func (c *snowflakeConnectionProducer) Connection(ctx context.Context) (interface{}, error) {
	// This is intentionally not grabbing the lock since the calling functions (e.g. CreateUser)
	// are claiming it.

	if !c.Initialized {
		return nil, connutil.ErrNotInitialized
	}

	if c.snowflakeDB != nil {
		return c.snowflakeDB, nil
	}

	var db *sql.DB
	var err error
	if len(c.PrivateKey) > 0 {
		db, err = openSnowflake(c.ConnectionURL)
		if err != nil {
			return nil, fmt.Errorf("error opening Snowflake connection using key-pair auth: %w", err)
		}
	} else {
		db, err = sql.Open(snowflakeSQLTypeName, c.ConnectionURL)
		if err != nil {
			return nil, fmt.Errorf("error opening Snowflake connection using user-pass auth: %w", err)
		}
	}

	c.snowflakeDB = db
	c.snowflakeDB.SetMaxOpenConns(c.MaxOpenConnections)
	c.snowflakeDB.SetMaxIdleConns(c.MaxIdleConnections)
	c.snowflakeDB.SetConnMaxLifetime(c.maxConnectionLifetime)

	return c.snowflakeDB, nil
}

// close terminates the database connection without locking
func (c *snowflakeConnectionProducer) close() error {
	if c.snowflakeDB != nil {
		if err := c.snowflakeDB.Close(); err != nil {
			return err
		}
	}

	return nil
}

// Close terminates the database connection with locking
func (c *snowflakeConnectionProducer) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.snowflakeDB = nil

	return c.close()
}

// Open the DB connection to Snowflake or return an error.
func openSnowflake(connectionURL string) (*sql.DB, error) {

	// Parse the connection_url - should be of the form
	// {username}@<account_name>.snowflakecomputing.com?authenticator=SNOWFLAKE_JWT&privateKey={private_key}
	snowflakeConfig, err := gosnowflake.ParseDSN(connectionURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection_url: %w", err)
	}

	connector := gosnowflake.NewConnector(gosnowflake.SnowflakeDriver{}, *snowflakeConfig)

	return sql.OpenDB(connector), nil
}
