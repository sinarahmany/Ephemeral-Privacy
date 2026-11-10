use rand::seq::IndexedRandom;

pub static REALISTIC_SEARCH_TOPICS: &[&str] = &[
    "sourdough fermentation ambient temperature humidity",
    "rust tokio async cancellation best practices",
    "james webb exoplanet transmission spectroscopy",
    "btrfs subvolumes automatic snapshot retention",
    "aeropress fine grind inverted technique",
    "sqlite wal mode concurrent read benchmarks",
    "mitochondria electron transport chain proton gradient",
    "bronze age collapse mediterranean tin trade",
    "webassembly simd performance rust wasm-pack",
    "drip irrigation system pressure regulator psi",
    "solar panel microinverter vs string inverter efficiency",
    "byzantine architecture hagia sophia pendentives",
    "linux kernel cgroups v2 memory pressure stall",
    "composting carbon nitrogen ratio autumn leaves",
    "cryptographic zero knowledge proof snark vs stark",
    "permaculture swale water retention contour",
    "cast iron seasoning polymerizing flaxseed oil",
    "gravitational wave interferometry ligo virgo",
    "arch linux pacman mirrors ranking reflector",
    "neovim treesitter custom query highlighting",
];

pub static DECOY_DNS_DOMAINS: &[&str] = &[
    "en.wikipedia.org",
    "crates.io",
    "docs.rs",
    "arxiv.org",
    "ncbi.nlm.nih.gov",
    "weather.gov",
    "archlinux.org",
    "gutenberg.org",
    "nasa.gov",
    "openstreetmap.org",
    "kernel.org",
    "mit.edu",
    "ietf.org",
    "w3.org",
    "eff.org",
    "archive.org",
    "mozilla.org",
    "distrowatch.com",
    "libreoffice.org",
    "blender.org",
];

pub static PRIVACY_SEARCH_ENDPOINTS: &[&str] = &[
    "https://html.duckduckgo.com/html/?q=",
    "https://search.brave.com/search?q=",
    "https://www.startpage.com/sp/search?query=",
];

/// Generates a realistic search query
pub fn random_search_query() -> &'static str {
    let mut rng = rand::rng();
    REALISTIC_SEARCH_TOPICS
        .choose(&mut rng)
        .copied()
        .unwrap_or("open source privacy tools")
}

/// Generates a realistic domain for DNS chaff
pub fn random_dns_domain() -> &'static str {
    let mut rng = rand::rng();
    DECOY_DNS_DOMAINS
        .choose(&mut rng)
        .copied()
        .unwrap_or("en.wikipedia.org")
}

/// Generates a decoy search URL targeted at a privacy search engine
pub fn random_decoy_search_url() -> String {
    let mut rng = rand::rng();
    let endpoint = PRIVACY_SEARCH_ENDPOINTS
        .choose(&mut rng)
        .copied()
        .unwrap_or("https://html.duckduckgo.com/html/?q=");
    let query = random_search_query();
    let encoded = urlencoding_simple(query);
    format!("{}{}", endpoint, encoded)
}

fn urlencoding_simple(s: &str) -> String {
    s.replace(' ', "+")
}
