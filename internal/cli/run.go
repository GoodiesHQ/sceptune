package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/goodieshq/sceptune/internal/crl"
	"github.com/goodieshq/sceptune/internal/scep"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"
	"golang.org/x/time/rate"
)

func run(ctx context.Context, c *cli.Command) error {
	if c.Bool("verbose") {
		log.Logger = log.Logger.Level(zerolog.DebugLevel)
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("Enabled verbose logging output")
	}

	// load the configuration parameters from CLI flags
	params, err := loadParams(c)
	if err != nil {
		return err
	}

	// create and start the SCEP server
	mux := chi.NewMux()

	// TODO: implement SCEP server for non-Windows platforms
	clientMS, clientStep, certStore, err := initialize(ctx, params)
	if err != nil {
		return err
	}

	// Create a SCEP server for Windows Intune clients
	scepServerWin := scep.NewSCEPServerWindows(params.RaCrt, params.RaKey,
		params.CaChain, clientMS, clientStep, certStore)

	// Create a CRL server backed by the Step CA server
	crlServer := crl.NewCrlServer(clientStep)

	// Rate limit middleware
	perIP := middlewareRateLimit(ctx, rate.Limit(5), 25)

	mux.Route(params.ScepPath, func(r chi.Router) {
		// Handlers for Windows SCEP clients
		r.Get("/pkiclient.exe", perIP(scepServerWin).ServeHTTP)
		r.Post("/pkiclient.exe", perIP(scepServerWin).ServeHTTP)
	})

	// CRL endpoint
	mux.Route(params.CRLPath, func(r chi.Router) {
		r.Get("/", perIP(crlServer).ServeHTTP)
	})

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", params.Port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		log.Warn().Msg("Shutting down SCEP server and cleaning up resources...")

		if err := certStore.Close(); err != nil {
			log.Error().Err(err).Msg("Error closing certificate store")
		}

		ctxShutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpServer.Shutdown(ctxShutdown)
	}()

	// Start purging revoked certificates
	scepServerWin.StartPurging(ctx)

	log.Info().Str("address", httpServer.Addr).Msg("Starting SCEP server...")
	err = httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("SCEP server error: %w", err)
	}

	return nil
}
