// Package lists downloads, caches and parses the domain and subnet lists a
// section routes.
package lists

import "sort"

// CommunityBase is the community-maintained list repository podkop and
// FlowCloud for Android use.
const CommunityBase = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/"

// Preset is one community list: a domain list and, for services with known
// address ranges, an IPv4 subnet list.
type Preset struct {
	Name    string
	Label   string
	Domains string // path under CommunityBase
	Subnets string // path under CommunityBase, optional
}

var presets = map[string]Preset{}

func add(name, label, domains, subnets string) {
	presets[name] = Preset{Name: name, Label: label, Domains: domains, Subnets: subnets}
}

func init() {
	add("russia_inside", "Russia inside", "Russia/inside-raw.lst", "")
	add("russia_outside", "Russia outside", "Russia/outside-raw.lst", "")
	add("ukraine_inside", "Ukraine", "Ukraine/inside-raw.lst", "")
	add("geoblock", "Geo Block", "Categories/geoblock.lst", "")
	add("block", "Block", "Categories/block.lst", "")
	add("porn", "Porn", "Categories/porn.lst", "")
	add("news", "News", "Categories/news.lst", "")
	add("anime", "Anime", "Categories/anime.lst", "")
	add("hodca", "HODCA", "Categories/hodca.lst", "")
	add("youtube", "YouTube", "Services/youtube.lst", "")
	add("hdrezka", "HDRezka", "Services/hdrezka.lst", "")
	add("tiktok", "TikTok", "Services/tiktok.lst", "")
	add("google_ai", "Google AI", "Services/google_ai.lst", "")
	add("google_play", "Google Play", "Services/google_play.lst", "")
	add("discord", "Discord", "Services/discord.lst", "Subnets/IPv4/discord.lst")
	add("meta", "Meta", "Services/meta.lst", "Subnets/IPv4/meta.lst")
	add("twitter", "Twitter (X)", "Services/twitter.lst", "Subnets/IPv4/twitter.lst")
	add("telegram", "Telegram", "Services/telegram.lst", "Subnets/IPv4/telegram.lst")
	add("roblox", "Roblox", "Services/roblox.lst", "Subnets/IPv4/roblox.lst")
	add("cloudflare", "Cloudflare", "Services/cloudflare.lst", "Subnets/IPv4/cloudflare.lst")
	add("cloudfront", "CloudFront", "Services/cloudfront.lst", "Subnets/IPv4/cloudfront.lst")
	add("digitalocean", "DigitalOcean", "Services/digitalocean.lst", "Subnets/IPv4/digitalocean.lst")
	add("hetzner", "Hetzner", "Services/hetzner.lst", "Subnets/IPv4/hetzner.lst")
	add("ovh", "OVH", "Services/ovh.lst", "Subnets/IPv4/ovh.lst")
}

// LookupPreset returns the community list with this name.
func LookupPreset(name string) (Preset, bool) {
	preset, ok := presets[name]
	return preset, ok
}

// Presets returns every community list, sorted by name.
func Presets() []Preset {
	result := make([]Preset, 0, len(presets))
	for _, preset := range presets {
		result = append(result, preset)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}
