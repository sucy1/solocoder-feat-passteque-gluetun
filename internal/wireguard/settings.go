package wireguard

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type Settings struct {
	// Interface name for the Wireguard interface.
	// It defaults to wg0 if unset.
	InterfaceName string
	// Private key in base 64 format
	PrivateKey string
	// Public key in base 64 format
	PublicKey string
	// Pre shared key in base 64 format
	PreSharedKey string
	// Wireguard server endpoint to connect to.
	Endpoint netip.AddrPort
	// Addresses assigned to the client.
	// Note IPv6 addresses are ignored if IPv6 is not supported.
	Addresses []netip.Prefix
	// AllowedIPs is the IP networks to be routed through
	// the Wireguard interface.
	// Note IPv6 addresses are ignored if IPv6 is not supported.
	AllowedIPs []netip.Prefix
	// PersistentKeepaliveInterval defines the keep alive interval, if not zero.
	PersistentKeepaliveInterval time.Duration
	// FirewallMark to be used in routing tables and IP rules.
	// It defaults to 51820 if left to 0.
	FirewallMark uint32
	// Maximum Transmission Unit (MTU) setting for the network interface.
	// It defaults to device.DefaultMTU from wireguard-go which is 1420
	MTU uint32
	// RulePriority is the priority for the rule created with the
	// FirewallMark.
	RulePriority uint32
	// IPv6 can bet set to true if IPv6 should be handled.
	// It defaults to false if left unset.
	IPv6 *bool
	// Implementation is the implementation to use.
	// It can be auto, kernelspace or userspace, and defaults to auto.
	Implementation string
	// Peers is the list of Wireguard peers to connect to.
	// If set, it takes precedence over the single-peer fields.
	Peers []Peer
}

type Peer struct {
	PublicKey                   string
	AllowedIPs                  []netip.Prefix
	Endpoint                    netip.AddrPort
	PersistentKeepaliveInterval time.Duration
}

func (s *Settings) SetDefaults() {
	if s.InterfaceName == "" {
		const defaultInterfaceName = "wg0"
		s.InterfaceName = defaultInterfaceName
	}

	if s.Endpoint.IsValid() && s.Endpoint.Port() == 0 {
		const defaultPort = 51820
		s.Endpoint = netip.AddrPortFrom(s.Endpoint.Addr(), defaultPort)
	}

	if s.FirewallMark == 0 {
		const defaultFirewallMark = 51820
		s.FirewallMark = defaultFirewallMark
	}

	if s.MTU == 0 {
		s.MTU = device.DefaultMTU
	}

	if s.IPv6 == nil {
		ipv6 := false // this should be injected from host
		s.IPv6 = &ipv6
	}

	if len(s.AllowedIPs) == 0 {
		s.AllowedIPs = append(s.AllowedIPs, allIPv4())
		if *s.IPv6 {
			s.AllowedIPs = append(s.AllowedIPs, allIPv6())
		}
	}

	if s.Implementation == "" {
		const defaultImplementation = "auto"
		s.Implementation = defaultImplementation
	}

	for i := range s.Peers {
		s.Peers[i].SetDefaults()
	}
}

var interfaceNameRegexp = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

func (s *Settings) Check() (err error) {
	if !interfaceNameRegexp.MatchString(s.InterfaceName) {
		return fmt.Errorf("invalid interface name: %s", s.InterfaceName)
	}

	if s.PrivateKey == "" {
		return errors.New("private key is missing")
	} else if _, err := wgtypes.ParseKey(s.PrivateKey); err != nil {
		return errors.New("cannot parse private key")
	}

	if len(s.Peers) > 0 {
		for i, peer := range s.Peers {
			if err := peer.Check(); err != nil {
				return fmt.Errorf("peer %d: %w", i, err)
			}
		}
		if len(s.Peers) > 1 {
			if err := checkNoPeerAllowedIPsOverlap(s.Peers); err != nil {
				return err
			}
		}
	} else {
		if s.PublicKey == "" {
			return errors.New("public key is missing")
		} else if _, err := wgtypes.ParseKey(s.PublicKey); err != nil {
			return fmt.Errorf("cannot parse public key: %s", s.PublicKey)
		}

		if s.PreSharedKey != "" {
			if _, err := wgtypes.ParseKey(s.PreSharedKey); err != nil {
				return errors.New("cannot parse pre-shared key")
			}
		}

		switch {
		case !s.Endpoint.Addr().IsValid():
			return errors.New("endpoint address is missing")
		case s.Endpoint.Port() == 0:
			return errors.New("endpoint port is missing")
		}
	}

	if len(s.Addresses) == 0 {
		return errors.New("interface address is missing")
	}
	for i, addr := range s.Addresses {
		if !addr.IsValid() {
			return fmt.Errorf("interface address is not valid: for address %d of %d",
				i+1, len(s.Addresses))
		}
	}

	if len(s.AllowedIPs) == 0 {
		return errors.New("allowed IPs are missing")
	}
	for i, allowedIP := range s.AllowedIPs {
		switch {
		case !allowedIP.IsValid():
			return fmt.Errorf("allowed IP is not valid: for allowed IP %d of %d",
				i+1, len(s.AllowedIPs))
		case allowedIP.Addr().Is6() && !*s.IPv6:
			return fmt.Errorf("allowed IPv6 address not supported: for allowed IP %s", allowedIP)
		}
	}

	if s.PersistentKeepaliveInterval < 0 {
		return fmt.Errorf("keep alive interval is negative: %s", s.PersistentKeepaliveInterval)
	}

	if s.FirewallMark == 0 {
		return errors.New("firewall mark is missing")
	}

	if s.MTU == 0 {
		return errors.New("MTU is missing")
	}

	switch s.Implementation {
	case "auto", "kernelspace", "userspace":
	default:
		return fmt.Errorf("invalid implementation: %s", s.Implementation)
	}

	return nil
}

func (s Settings) String() string {
	lines := s.ToLines(ToLinesSettings{})
	return strings.Join(lines, "\n")
}

type ToLinesSettings struct {
	// Indent defaults to 4 spaces "    ".
	Indent *string
	// FieldPrefix defaults to "├── ".
	FieldPrefix *string
	// LastFieldPrefix defaults to "└── ".
	LastFieldPrefix *string
}

func (settings *ToLinesSettings) setDefaults() {
	toStringPtr := func(s string) *string { return &s }
	if settings.Indent == nil {
		settings.Indent = toStringPtr("    ")
	}
	if settings.FieldPrefix == nil {
		settings.FieldPrefix = toStringPtr("├── ")
	}
	if settings.LastFieldPrefix == nil {
		settings.LastFieldPrefix = toStringPtr("└── ")
	}
}

// ToLines serializes the settings to a slice of strings for display.
func (s Settings) ToLines(settings ToLinesSettings) (lines []string) {
	settings.setDefaults()

	indent := *settings.Indent
	fieldPrefix := *settings.FieldPrefix
	lastFieldPrefix := *settings.LastFieldPrefix

	lines = append(lines, fieldPrefix+"Interface name: "+s.InterfaceName)
	const (
		set    = "set"
		notSet = "not set"
	)

	isSet := notSet
	if s.PrivateKey != "" {
		isSet = set
	}
	lines = append(lines, fieldPrefix+"Private key: "+isSet)

	if s.PublicKey != "" {
		lines = append(lines, fieldPrefix+"PublicKey: "+s.PublicKey)
	}

	isSet = notSet
	if s.PreSharedKey != "" {
		isSet = set
	}
	lines = append(lines, fieldPrefix+"Pre shared key: "+isSet)

	endpointStr := notSet
	if s.Endpoint.Addr().IsValid() {
		endpointStr = s.Endpoint.String()
	}
	lines = append(lines, fieldPrefix+"Endpoint: "+endpointStr)

	ipv6Status := "disabled"
	if *s.IPv6 {
		ipv6Status = "enabled"
	}
	lines = append(lines, fieldPrefix+"IPv6: "+ipv6Status)

	if s.FirewallMark != 0 {
		lines = append(lines, fieldPrefix+"Firewall mark: "+fmt.Sprint(s.FirewallMark))
	}

	if s.MTU != 0 {
		lines = append(lines, fieldPrefix+"MTU: "+fmt.Sprint(s.MTU))
	}

	if s.RulePriority != 0 {
		lines = append(lines, fieldPrefix+"Rule priority: "+fmt.Sprint(s.RulePriority))
	}

	if s.Implementation != "auto" {
		lines = append(lines, fieldPrefix+"Implementation: "+s.Implementation)
	}

	if len(s.Addresses) == 0 {
		lines = append(lines, lastFieldPrefix+"Addresses: "+notSet)
	} else {
		lines = append(lines, lastFieldPrefix+"Addresses:")
		for i, address := range s.Addresses {
			prefix := fieldPrefix
			if i == len(s.Addresses)-1 {
				prefix = lastFieldPrefix
			}
			lines = append(lines, indent+prefix+address.String())
		}
	}

	if len(s.AllowedIPs) > 0 {
		lines = append(lines, fieldPrefix+"Allowed IPs:")
		for i, allowedIP := range s.AllowedIPs {
			prefix := fieldPrefix
			if i == len(s.AllowedIPs)-1 {
				prefix = lastFieldPrefix
			}
			lines = append(lines, indent+prefix+allowedIP.String())
		}
	}

	if s.PersistentKeepaliveInterval > 0 {
		lines = append(lines, fieldPrefix+"Persistent keep alive interval: "+
			s.PersistentKeepaliveInterval.String())
	}

	if len(s.Peers) > 0 {
		peersLines := []string{fieldPrefix + "Peers:"}
		for i, peer := range s.Peers {
			peerLines := peer.ToLines(ToLinesSettings{
				Indent:          settings.Indent,
				FieldPrefix:     settings.FieldPrefix,
				LastFieldPrefix: settings.LastFieldPrefix,
			})
			peersLines = append(peersLines, indent+fieldPrefix+fmt.Sprintf("Peer %d:", i))
			for _, peerLine := range peerLines {
				peersLines = append(peersLines, indent+indent+peerLine)
			}
		}
		lines = append(lines, peersLines...)
	}

	return lines
}

func (p *Peer) SetDefaults() {
	if p.Endpoint.IsValid() && p.Endpoint.Port() == 0 {
		const defaultPort = 51820
		p.Endpoint = netip.AddrPortFrom(p.Endpoint.Addr(), defaultPort)
	}

	if len(p.AllowedIPs) == 0 {
		p.AllowedIPs = append(p.AllowedIPs, allIPv4())
	}
}

func (p Peer) Check() (err error) {
	if p.PublicKey == "" {
		return errors.New("public key is missing")
	} else if _, err := wgtypes.ParseKey(p.PublicKey); err != nil {
		return fmt.Errorf("cannot parse public key: %s", p.PublicKey)
	}

	switch {
	case !p.Endpoint.Addr().IsValid():
		return errors.New("endpoint address is missing")
	case p.Endpoint.Port() == 0:
		return errors.New("endpoint port is missing")
	}

	if len(p.AllowedIPs) == 0 {
		return errors.New("allowed IPs are missing")
	}
	for i, allowedIP := range p.AllowedIPs {
		if !allowedIP.IsValid() {
			return fmt.Errorf("allowed IP is not valid: for allowed IP %d of %d",
				i+1, len(p.AllowedIPs))
		}
	}

	if p.PersistentKeepaliveInterval < 0 {
		return fmt.Errorf("keep alive interval is negative: %s", p.PersistentKeepaliveInterval)
	}

	return nil
}

func (p Peer) ToLines(settings ToLinesSettings) (lines []string) {
	settings.setDefaults()

	fieldPrefix := *settings.FieldPrefix

	if p.PublicKey != "" {
		lines = append(lines, fieldPrefix+"PublicKey: "+p.PublicKey)
	}

	endpointStr := "not set"
	if p.Endpoint.Addr().IsValid() {
		endpointStr = p.Endpoint.String()
	}
	lines = append(lines, fieldPrefix+"Endpoint: "+endpointStr)

	if len(p.AllowedIPs) > 0 {
		lines = append(lines, fieldPrefix+"Allowed IPs:")
		for _, allowedIP := range p.AllowedIPs {
			lines = append(lines, *settings.Indent+fieldPrefix+allowedIP.String())
		}
	}

	if p.PersistentKeepaliveInterval > 0 {
		lines = append(lines, fieldPrefix+"Persistent keep alive interval: "+
			p.PersistentKeepaliveInterval.String())
	}

	return lines
}

func checkNoPeerAllowedIPsOverlap(peers []Peer) (err error) {
	type allowedIPInfo struct {
		peerIndex int
		prefix    netip.Prefix
	}
	var allAllowedIPs []allowedIPInfo
	for i, peer := range peers {
		for _, prefix := range peer.AllowedIPs {
			allAllowedIPs = append(allAllowedIPs, allowedIPInfo{
				peerIndex: i,
				prefix:    prefix,
			})
		}
	}

	for i := range allAllowedIPs {
		for j := i + 1; j < len(allAllowedIPs); j++ {
			a := allAllowedIPs[i]
			b := allAllowedIPs[j]
			if a.peerIndex == b.peerIndex {
				continue
			}
			if peerPrefixesOverlap(a.prefix, b.prefix) {
				return fmt.Errorf("allowed IPs overlap between peer %d (%s) and peer %d (%s)",
					a.peerIndex, a.prefix, b.peerIndex, b.prefix)
			}
		}
	}
	return nil
}

func peerPrefixesOverlap(a, b netip.Prefix) bool {
	return a.Contains(b.Addr()) || b.Contains(a.Addr())
}
