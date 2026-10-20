//go:build !novpn

package vpn

import (
    "errors"
    "fmt"
    "io/fs"
    "os"

    C "github.com/sagernet/sing-box/constant"
    O "github.com/sagernet/sing-box/option"
    "github.com/sagernet/sing/common/json"

    "github.com/getlantern/radiance/common/atomicfile"
    "github.com/getlantern/radiance/common/fileperm"
)

const splitTunnelCIDRResolveTag = "split-tunnel-cidr-resolve"

func (s *SplitTunnel) cidrResolverBytesLocked() ([]byte, error) {
    rule := defaultRule().Rules[0]
    if s.rule.Mode == C.LogicalTypeOr && len(s.ruleMap[TypeIPCIDR].IPCIDR) > 0 {
        rule = O.HeadlessRule{
            Type: C.RuleTypeDefault,
            DefaultOptions: O.DefaultHeadlessRule{DomainRegex: []string{".+"}},
        }
    }
    return json.Marshal(O.PlainRuleSetCompat{
        Version: 3,
        Options: O.PlainRuleSet{Rules: []O.HeadlessRule{rule}},
    })
}

func (s *SplitTunnel) saveCIDRResolverLocked() error {
    gate, err := s.cidrResolverBytesLocked()
    if err != nil {
        return err
    }
    return atomicfile.WriteFile(s.resolverFile, gate, fileperm.File)
}

func (s *SplitTunnel) writeRuleFilesLocked(primary []byte) error {
    gate, err := s.cidrResolverBytesLocked()
    if err != nil {
        return err
    }
    previous, readErr := os.ReadFile(s.resolverFile)
    if readErr != nil && !errors.Is(readErr, fs.ErrNotExist) {
        return fmt.Errorf("reading CIDR resolver gate: %w", readErr)
    }
    if err := atomicfile.WriteFile(s.resolverFile, gate, fileperm.File); err != nil {
        return fmt.Errorf("writing CIDR resolver gate: %w", err)
    }
    if err := atomicfile.WriteFile(s.ruleFile, primary, fileperm.File); err != nil {
        var rollbackErr error
        if readErr == nil {
            rollbackErr = atomicfile.WriteFile(s.resolverFile, previous, fileperm.File)
        } else {
            rollbackErr = os.Remove(s.resolverFile)
            if errors.Is(rollbackErr, fs.ErrNotExist) {
                rollbackErr = nil
            }
        }
        return errors.Join(fmt.Errorf("writing split-tunnel filters: %w", err), rollbackErr)
    }
    return nil
}
