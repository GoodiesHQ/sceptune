package cli

import (
	"context"
	"fmt"

	"github.com/goodieshq/sceptune/pkg/ms"
	"github.com/goodieshq/sceptune/pkg/scep"
	"github.com/goodieshq/sceptune/pkg/step"
	"github.com/goodieshq/sceptune/pkg/store"
	"github.com/goodieshq/sceptune/pkg/utils"
	"github.com/rs/zerolog/log"
)

func initialize(ctx context.Context, params *Params) (scep.Verifier, scep.Signer, scep.Store, error) {
	// Create a microsoft client to interact with Graph and Intune APIs
	msClient, err := ms.NewMSClient(
		params.TenantID,
		params.ClientID,
		params.ClientSecret,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create MS client: %w", err)
	}
	err = msClient.PopulateScepEndpoint(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to populate Intune SCEP endpoint from Microsoft Graph: %w", err)
	}
	log.Info().Msg("[+] Confirmed ability to Populate Intune SCEP endpoint from Microsoft Graph")
	_, err = msClient.GetIntuneToken(ctx) // warm up the token cache
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to verify test CSR with Intune: %w", err)
	}
	log.Info().Msg("[+] Confirmed ability to Verify CSR with Intune")

	// Create a Step client to sign CSRs
	stepClient, err := step.NewStepClient(
		params.APIURL,
		params.ProvisionerName,
		utils.FingerprintSha256(params.CaCrt),
		params.JWK,
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create Step client: %w", err)
	}
	log.Info().Msg("[+] Initialized Step client for signing CSRs")

	// Create a data store for issued certificates
	certStore, err := store.NewCertificateStore(params.DBPath)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to initialize certificate store: %w", err)
	}

	log.Info().Msg("[+] Initialized certificate store database")

	return msClient, stepClient, certStore, nil
}
