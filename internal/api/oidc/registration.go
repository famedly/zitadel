package oidc

import (
	"context"

	"github.com/zitadel/oidc/v3/pkg/oidc"
	"github.com/zitadel/oidc/v3/pkg/op"

	"github.com/zitadel/zitadel/internal/query"
	"github.com/zitadel/zitadel/internal/telemetry/tracing"
	"github.com/zitadel/zitadel/internal/zerrors"
)

func (s *Server) RegisterClient(ctx context.Context, r *op.Request[oidc.ClientRegistrationRequest]) (resp *op.Response, err error) {
	ctx, span := tracing.NewSpan(ctx)
	defer func() {
		err = oidcError(err)
		span.EndWithError(err)
	}()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var searchQueries []query.SearchQuery
	for _, uri := range r.Data.RedirectURIs {
		per, err := query.NewAppRedirectURIsSearchQuery(uri)
		if err != nil {
			return nil, err
		}
		searchQueries = append(searchQueries, per)
	}

	queries := &query.AppSearchQueries{
		SearchRequest: query.SearchRequest{
			Offset: 0,
			Limit:  3,
			Asc:    true,
		},
		Queries: searchQueries,
	}

	apps, err := s.query.SearchClientIDs(ctx, queries, false)

	if err != nil {
		return nil, err
	}

	if len(apps) < 1 {
		return nil, zerrors.ThrowNotFound(err, "DCR-1", "Client not found")
	}

	client_information := oidc.ClientInformationResponse{
		ClientMetadata: r.Data.ClientMetadata,
		ClientID:       apps[0],
	}

	return op.NewResponse(&oidc.ClientRegistrationResponse{ClientInformationResponse: client_information}), nil
}
