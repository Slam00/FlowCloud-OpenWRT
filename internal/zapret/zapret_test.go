package zapret

import (
	"strings"
	"testing"
)

func TestArgs(t *testing.T) {
	strategy, ok := Lookup("seqovl")
	if !ok {
		t.Fatal("seqovl strategy is missing")
	}
	args := strings.Join(Args("/usr/lib/flowcloud/zapret2", "/usr/lib/flowcloud/zapret2/lua", 300, strategy, ""), " ")
	for _, want := range []string{
		"--qnum=300",
		"--fwmark=0x40000000",
		"--lua-init=@/usr/lib/flowcloud/zapret2/lua/zapret-lib.lua",
		"--filter-tcp=443 --filter-l7=tls --payload=tls_client_hello --lua-desync=multisplit:pos=1:seqovl=5 --new",
		"--filter-udp=443 --filter-l7=quic",
	} {
		if !strings.Contains(args, want) {
			t.Errorf("args lack %q:\n%s", want, args)
		}
	}
	custom := strings.Join(Args("/x", "/x/lua", 200, Strategy{}, " --filter-tcp=443  --lua-desync=multidisorder:pos=1 "), " ")
	if !strings.HasSuffix(custom, "--filter-tcp=443 --lua-desync=multidisorder:pos=1") || strings.Contains(custom, "quic") {
		t.Fatalf("custom args must replace the built-in profiles: %s", custom)
	}
}

func TestStrategyNamesAreUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, strategy := range Strategies {
		if seen[strategy.Name] || strategy.TLS == "" {
			t.Fatalf("bad strategy %+v", strategy)
		}
		seen[strategy.Name] = true
	}
}

func TestAllOK(t *testing.T) {
	if AllOK(nil) || !AllOK([]URLResult{{OK: true}}) || AllOK([]URLResult{{OK: true}, {}}) || !AnyOK([]URLResult{{}, {OK: true}}) {
		t.Fatal("result helpers are wrong")
	}
}
