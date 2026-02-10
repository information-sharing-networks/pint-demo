package commonhandlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/information-sharing-networks/pint-demo/app/internal/database"
	"github.com/information-sharing-networks/pint-demo/app/internal/logger"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// request and responses

type PartyRequest struct {
	PartyName string `json:"party_name"`
	Active    *bool  `json:"active"`
}

type PartyResponse struct {
	ID        string `json:"id"`
	PartyName string `json:"party_name"`
	Active    bool   `json:"active"`
}

type PartyIdentifyingCodeRequest struct {
	CodeListProvider string  `json:"code_list_provider"`
	PartyCode        string  `json:"party_code"`
	CodeListName     *string `json:"code_list_name,omitempty"`
}

type PartyIdentifyingCodeResponse struct {
	ID               string  `json:"id"`
	PartyID          string  `json:"party_id"`
	CodeListProvider string  `json:"code_list_provider"`
	PartyCode        string  `json:"party_code"`
	CodeListName     *string `json:"code_list_name,omitempty"`
}

// HandleCreateParty godoc
//
//	@Summary	Create a new party
//	@Tags		Admin
//	@Accept		json
//	@Produce	json
//	@Param		party	body		PartyRequest	true	"Party details"
//	@Success	201		{object}	PartyResponse
//	@Failure	400		{string}	string	"Invalid request"
//	@Router		/admin/parties [post]
func HandleCreateParty(queries *database.Queries) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqLogger := logger.ContextRequestLogger(r.Context())

		var req PartyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.PartyName == "" {
			http.Error(w, "party_name is required", http.StatusBadRequest)
			return
		}

		// Default active to true if not specified
		active := true
		if req.Active != nil {
			active = *req.Active
		}

		party, err := queries.CreateParty(r.Context(), database.CreatePartyParams{
			PartyName: req.PartyName,
			Active:    active,
		})
		if err != nil {
			returnErr := fmt.Errorf("failed to create party - internal error")
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) {
				// Check for unique violation error code
				if pgErr.Code == "23505" {
					// Handle duplicate key error
					returnErr = fmt.Errorf("party already exists")
				}
			}
			reqLogger.Error("failed to create party", slog.String("error", err.Error()))
			http.Error(w, returnErr.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(partyToResponse(party)); err != nil {
			reqLogger.Error("failed to encode response", slog.String("error", err.Error()))
		}
	}
}

// HandleUpdateParty godoc
//
//	@Summary	Update an existing party
//	@Tags		Admin
//	@Accept		json
//	@Produce	json
//	@Param		partyID	path		string			true	"Party ID"
//	@Param		party	body		PartyRequest	true	"Party details"
//	@Success	200		{object}	PartyResponse
//	@Failure	400		{string}	string	"Invalid request"
//	@Failure	404		{string}	string	"Party not found"
//	@Router		/admin/parties/{partyID} [put]
func HandleUpdateParty(queries *database.Queries) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqLogger := logger.ContextRequestLogger(r.Context())
		partyIDStr := chi.URLParam(r, "partyID")

		partyID, err := uuid.Parse(partyIDStr)
		if err != nil {
			http.Error(w, "Invalid party ID", http.StatusBadRequest)
			return
		}

		var req PartyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		// Check if at least one field is provided
		if req.PartyName == "" && req.Active == nil {
			http.Error(w, "party_name or active status is required", http.StatusBadRequest)
			return
		}

		// Fetch existing party to preserve unmodified fields
		existingParty, err := queries.GetPartyByID(r.Context(), partyID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "Party not found", http.StatusNotFound)
				return
			}
			reqLogger.Error("failed to fetch party", slog.String("error", err.Error()))
			http.Error(w, "Failed to fetch party", http.StatusInternalServerError)
			return
		}

		if req.Active == nil {
			req.Active = &existingParty.Active
		}

		party, err := queries.UpdateParty(r.Context(), database.UpdatePartyParams{
			ID:        partyID,
			PartyName: req.PartyName,
			Active:    *req.Active,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "Party not found", http.StatusNotFound)
				return
			}
			reqLogger.Error("failed to update party", slog.String("error", err.Error()))
			http.Error(w, "Failed to update party", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(partyToResponse(party)); err != nil {
			reqLogger.Error("failed to encode response", slog.String("error", err.Error()))
		}
	}
}

// HandleGetPartyByID godoc
//
//	@Summary	Get party by ID
//	@Tags		Admin
//	@Produce	json
//	@Param		partyID	path		string	true	"Party ID"
//	@Success	200		{object}	PartyResponse
//	@Failure	400		{string}	string	"Invalid party ID"
//	@Failure	404		{string}	string	"Party not found"
//	@Router		/admin/parties/{partyID} [get]
func HandleGetPartyByID(queries *database.Queries) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqLogger := logger.ContextRequestLogger(r.Context())
		partyIDStr := chi.URLParam(r, "partyID")

		partyID, err := uuid.Parse(partyIDStr)
		if err != nil {
			http.Error(w, "Invalid party ID", http.StatusBadRequest)
			return
		}

		party, err := queries.GetPartyByID(r.Context(), partyID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "Party not found", http.StatusNotFound)
				return
			}
			reqLogger.Error("failed to get party", slog.String("error", err.Error()))
			http.Error(w, "Failed to get party", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(partyToResponse(party)); err != nil {
			reqLogger.Error("failed to encode response", slog.String("error", err.Error()))
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			return
		}
	}
}

// HandleGetPartyByPartyName godoc
//
//	@Summary	Get party by party name
//	@Tags		Admin
//	@Produce	json
//	@Param		partyName	path		string	true	"Party name"
//	@Success	200			{object}	PartyResponse
//	@Failure	404			{string}	string	"Party not found"
//	@Router		/admin/parties/{partyName} [get]
func HandleGetPartyByPartyName(queries *database.Queries) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqLogger := logger.ContextRequestLogger(r.Context())
		partyName := chi.URLParam(r, "partyName")

		party, err := queries.GetPartyByPartyName(r.Context(), partyName)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "Party not found !!!!", http.StatusNotFound)
				return
			}
			reqLogger.Error("failed to get party", slog.String("error", err.Error()))
			http.Error(w, "Failed to get party", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(partyToResponse(party)); err != nil {
			reqLogger.Error("failed to encode response", slog.String("error", err.Error()))
			http.Error(w, "Failed to encode response", http.StatusInternalServerError)
			return
		}
	}
}

// HandleCreatePartyIdentifyingCode godoc
//
//	@Summary	Add an identifying code to a party
//	@Tags		Admin
//	@Accept		json
//	@Produce	json
//	@Param		partyID	path		string						true	"Party ID"
//	@Param		code	body		PartyIdentifyingCodeRequest	true	"Code details"
//	@Success	201		{object}	PartyIdentifyingCodeResponse
//	@Failure	400		{string}	string	"Invalid request"
//	@Router		/admin/parties/{partyID}/codes [post]
func HandleCreatePartyIdentifyingCode(queries *database.Queries) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqLogger := logger.ContextRequestLogger(r.Context())
		partyIDStr := chi.URLParam(r, "partyID")

		partyID, err := uuid.Parse(partyIDStr)
		if err != nil {
			http.Error(w, "Invalid party ID", http.StatusBadRequest)
			return
		}

		var req PartyIdentifyingCodeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid request body", http.StatusBadRequest)
			return
		}

		if req.CodeListProvider == "" || req.PartyCode == "" {
			http.Error(w, "code_list_provider and party_code are required", http.StatusBadRequest)
			return
		}

		code, err := queries.CreatePartyIdentifyingCode(r.Context(), database.CreatePartyIdentifyingCodeParams{
			PartyID:          partyID,
			CodeListProvider: req.CodeListProvider,
			PartyCode:        req.PartyCode,
			CodeListName:     req.CodeListName,
		})
		if err != nil {
			// check for duplicates
			var pgErr *pgconn.PgError
			returnErr := fmt.Errorf("failed to create party identifying code - internal error")
			if errors.As(err, &pgErr) {
				// Check for unique violation error code
				if pgErr.Code == "23505" {
					// Handle duplicate key error
					returnErr = fmt.Errorf("party identifier code already exists")
				}
			}
			reqLogger.Error("failed to create party identifying code", slog.String("error", err.Error()))
			http.Error(w, returnErr.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		if err := json.NewEncoder(w).Encode(partyIdentifyingCodeToResponse(code)); err != nil {
			reqLogger.Error("failed to encode response", slog.String("error", err.Error()))
		}
	}
}

// HandleGetPartyByPartyCode godoc
//
//	@Summary	Get party by party code
//	@Tags		Admin
//	@Produce	json
//	@Param		code_list_provider	query		string	true	"Code list provider"
//	@Param		code_list_name		query		string	false	"Code list name (optional)"
//	@Param		party_code			query		string	true	"Party code"
//	@Success	200					{object}	PartyResponse
//	@Failure	400					{string}	string	"Invalid request"
//	@Failure	404					{string}	string	"Party not found"
//	@Router		/admin/parties/ [get]
func HandleGetPartyByPartyCode(queries *database.Queries) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqLogger := logger.ContextRequestLogger(r.Context())
		codeListProvider := r.URL.Query().Get("code_list_provider")
		partyCode := r.URL.Query().Get("party_code")

		if codeListProvider == "" || partyCode == "" {
			http.Error(w, "code_list_provider and party_code are required", http.StatusBadRequest)
			return
		}

		// Handle optional code_list_name
		var codeListName *string
		if name := r.URL.Query().Get("code_list_name"); name != "" {
			codeListName = &name
		}

		party, err := queries.GetPartyByPartyCode(r.Context(), database.GetPartyByPartyCodeParams{
			CodeListProvider: codeListProvider,
			PartyCode:        partyCode,
			CodeListName:     codeListName,
		})
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				http.Error(w, "Party not found", http.StatusNotFound)
				return
			}
			reqLogger.Error("failed to get party", slog.String("error", err.Error()))
			http.Error(w, "Failed to get party", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(partyToResponse(party)); err != nil {
			reqLogger.Error("failed to encode response", slog.String("error", err.Error()))
		}
	}
}

// Helper functions to convert database models to response types

func partyToResponse(party database.Party) PartyResponse {
	return PartyResponse{
		ID:        party.ID.String(),
		PartyName: party.PartyName,
		Active:    party.Active,
	}
}

func partyIdentifyingCodeToResponse(code database.PartyIdentifyingCode) PartyIdentifyingCodeResponse {
	return PartyIdentifyingCodeResponse{
		ID:               code.ID.String(),
		PartyID:          code.PartyID.String(),
		CodeListProvider: code.CodeListProvider,
		PartyCode:        code.PartyCode,
		CodeListName:     code.CodeListName,
	}
}
