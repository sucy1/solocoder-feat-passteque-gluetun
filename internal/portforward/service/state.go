package service

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type PortForwardState struct {
	Ports     []uint16  `json:"ports"`
	ExpiresAt time.Time `json:"expires_at"`
	SessionID string    `json:"session_id"`
}

func (s *Service) writeStateFile(state PortForwardState) error {
	if s.settings.StateFilepath == "" {
		return nil
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling port forward state: %w", err)
	}
	const perm = 0o600
	err = os.WriteFile(s.settings.StateFilepath, data, perm)
	if err != nil {
		return fmt.Errorf("writing port forward state file: %w", err)
	}
	err = os.Chown(s.settings.StateFilepath, s.puid, s.pgid)
	if err != nil {
		return fmt.Errorf("chowning port forward state file: %w", err)
	}
	return nil
}

func (s *Service) readStateFile() (PortForwardState, error) {
	var state PortForwardState
	if s.settings.StateFilepath == "" {
		return state, nil
	}
	data, err := os.ReadFile(s.settings.StateFilepath)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}
		return state, fmt.Errorf("reading port forward state file: %w", err)
	}
	err = json.Unmarshal(data, &state)
	if err != nil {
		return state, fmt.Errorf("unmarshaling port forward state: %w", err)
	}
	return state, nil
}

func (s *Service) LoadPersistedState() (ports []uint16, valid bool, err error) {
	state, err := s.readStateFile()
	if err != nil {
		return nil, false, err
	}
	if len(state.Ports) == 0 {
		return nil, false, nil
	}
	if !state.ExpiresAt.IsZero() && time.Now().After(state.ExpiresAt) {
		s.logger.Info("persisted port forward state expired, ignoring")
		return nil, false, nil
	}
	s.logger.Infof("restored port forward state from file: %d port(s)", len(state.Ports))
	return state.Ports, true, nil
}

func (s *Service) clearStateFile() error {
	if s.settings.StateFilepath == "" {
		return nil
	}
	const perm = 0o600
	err := os.WriteFile(s.settings.StateFilepath, []byte("{}"), perm)
	if err != nil {
		return fmt.Errorf("clearing port forward state file: %w", err)
	}
	err = os.Chown(s.settings.StateFilepath, s.puid, s.pgid)
	if err != nil {
		return fmt.Errorf("chowning port forward state file: %w", err)
	}
	return nil
}
