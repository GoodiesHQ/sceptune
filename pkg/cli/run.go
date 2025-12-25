package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path"
	"time"

	"github.com/goodieshq/sceptune/pkg/scep"
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

	params, err := loadParams(c)
	if err != nil {
		return err
	}

	// create and start the SCEP server
	mux := http.NewServeMux()

	// TODO: implement SCEP server for non-Windows platforms

	msClient, clientStep, certStore, err := initialize(ctx, params)
	if err != nil {
		return err
	}

	log.Info().Msg("======= SCEP Server Configuration Complete =======")

	// Create a SCEP server for Windows Intune clients
	srvWin := scep.NewSCEPServerWindows(
		params.RaCrt,
		params.RaKey,
		params.CaChain,
		msClient,
		clientStep,
		certStore,
	)

	perIP := middlewareRateLimit(ctx, rate.Limit(5), 25)
	scepPathWindows := path.Join(params.ScepPath, "pkiclient.exe")

	// Windows SCEP clients
	mux.Handle(scepPathWindows, perIP(srvWin))

	// CRL endpoint
	mux.Handle(params.CRLPath, perIP(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		crl, err := clientStep.GetCRL(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get CRL: %v", err), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/pkix-crl")
		w.WriteHeader(http.StatusOK)
		w.Write(crl.Raw)
	})))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}

		// Simple text-only landing page
		fmt.Fprintf(w, "SCEP Server Running\n")
		fmt.Fprintf(w, "SCEP Endpoint (Windows): %s? operation=<operation>\n", scepPathWindows)
		fmt.Fprintf(w, "  - GetCACaps\n")
		fmt.Fprintf(w, "  - GetCACert\n")
		fmt.Fprintf(w, "  - PKIOperation\n")
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

	srvWin.StartPurging(ctx)

	log.Info().Str("address", httpServer.Addr).Msg("Starting SCEP server...")
	err = httpServer.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("SCEP server error: %w", err)
	}

	return nil
}
