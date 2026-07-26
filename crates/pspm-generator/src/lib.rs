use pspm_core::types::{GenerationPolicy, PasswordStyle};
use rand::Rng;

pub struct PasswordGenerator;

impl PasswordGenerator {
    pub fn generate(policy: &GenerationPolicy) -> String {
        match policy.style {
            PasswordStyle::Random => Self::generate_random(policy),
            PasswordStyle::Diceware => Self::generate_diceware(),
            PasswordStyle::Pin => Self::generate_pin(policy),
            PasswordStyle::Memorable => Self::generate_memorable(),
        }
    }

    fn generate_random(policy: &GenerationPolicy) -> String {
        let mut rng = rand::thread_rng();
        let mut chars = Vec::new();

        let lower: Vec<char> = "abcdefghijklmnopqrstuvwxyz".chars().collect();
        let upper: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".chars().collect();
        let digits: Vec<char> = "0123456789".chars().collect();
        let symbols: Vec<char> = "!@#$%^&*()_+-=[]{}|;:,.<>?".chars().collect();
        let ambiguous: &[char] = &['1', 'l', 'I', '0', 'O', 'o'];

        let mut pool: Vec<char> = Vec::new();
        let mut guaranteed = Vec::new();

        if policy.include_lowercase {
            let filtered: Vec<char> = lower.iter().copied().filter(|c| !policy.no_ambiguous || !ambiguous.contains(c)).collect();
            pool.extend(&lower);
            guaranteed.push(*filtered.first().unwrap_or_else(|| &lower[rng.gen_range(0..lower.len())]));
        }
        if policy.include_uppercase {
            let filtered: Vec<char> = upper.iter().copied().filter(|c| !policy.no_ambiguous || !ambiguous.contains(c)).collect();
            pool.extend(&upper);
            guaranteed.push(*filtered.first().unwrap_or_else(|| &upper[rng.gen_range(0..upper.len())]));
        }
        if policy.include_digits {
            let filtered: Vec<char> = digits.iter().copied().filter(|c| !policy.no_ambiguous || !ambiguous.contains(c)).collect();
            pool.extend(&digits);
            guaranteed.push(*filtered.first().unwrap_or_else(|| &digits[rng.gen_range(0..digits.len())]));
        }
        if policy.include_symbols {
            pool.extend(&symbols);
            guaranteed.push(symbols[rng.gen_range(0..symbols.len())]);
        }

        if policy.no_ambiguous {
            pool.retain(|c| !ambiguous.contains(c));
        }

        if pool.is_empty() {
            pool.extend(&lower);
            pool.extend(&digits);
        }

        let remaining = policy.length as usize - guaranteed.len();
        for _ in 0..remaining {
            let idx = rng.gen_range(0..pool.len());
            chars.push(pool[idx]);
        }
        chars.extend(guaranteed);

        for i in (1..chars.len()).rev() {
            let j = rng.gen_range(0..=i);
            chars.swap(i, j);
        }

        chars.into_iter().collect()
    }

    fn generate_diceware() -> String {
        let mut rng = rand::thread_rng();
        let selected: Vec<&str> = (0..6).map(|_| DICEWARE_WORDS[rng.gen_range(0..DICEWARE_WORDS.len())]).collect();
        selected.join("-")
    }

    fn generate_pin(policy: &GenerationPolicy) -> String {
        let mut rng = rand::thread_rng();
        let len = policy.length.clamp(4, 12) as usize;
        (0..len)
            .map(|_| rng.gen_range(0..10).to_string())
            .collect()
    }

    fn generate_memorable() -> String {
        let mut rng = rand::thread_rng();
        let adj = MEMORABLE_ADJECTIVES[rng.gen_range(0..MEMORABLE_ADJECTIVES.len())];
        let noun = MEMORABLE_NOUNS[rng.gen_range(0..MEMORABLE_NOUNS.len())];
        let num: u32 = rng.gen_range(10..999);
        format!("{adj}{noun}{num}")
    }
}

const DICEWARE_WORDS: &[&str] = &[
    "ability", "absence", "academy", "account", "achieve", "acquire", "address", "advance",
    "adverse", "analysis", "ancient", "another", "anxiety", "anybody", "applied", "arrange",
    "article", "assault", "attempt", "attract", "auction", "average", "awesome", "balance",
    "barrier", "battery", "beneath", "benefit", "billion", "biology", "blanket", "blessed",
    "bracket", "breath", "briefly", "broadly", "brother", "builder", "cabinet", "caliber",
    "camera", "campaign", "capable", "capital", "capture", "careful", "catalyst", "caution",
    "ceiling", "central", "century", "chamber", "channel", "chapter", "charity", "chicken",
    "circuit", "citizen", "civilian", "classic", "climate", "closure", "clothing", "cluster",
    "coalition", "coastal", "collect", "comfort", "command", "comment", "company", "compare",
    "compete", "complex", "compose", "concept", "concern", "conduct", "confirm", "connect",
    "consent", "consult", "contact", "contain", "contest", "context", "control", "convert",
    "cooking", "council", "counter", "country", "courage", "creator", "cricket", "crystal",
    "culture", "current", "cushion", "custom", "dancing", "danger", "database", "daughter",
    "deadline", "dealer", "debate", "debtor", "decade", "decide", "declare", "decline",
    "default", "defense", "deficit", "deliver", "density", "deposit", "deputy", "derived",
    "deserve", "design", "desktop", "despite", "destiny", "destroy", "details", "detect",
    "develop", "devoted", "diamond", "digital", "discuss", "disease", "display", "dispute",
    "distant", "diverse", "divided", "donation", "double", "dragon", "drama", "drastic",
    "drought", "dynamic", "eastern", "economy", "edition", "educate", "elderly", "elected",
    "element", "embrace", "emotion", "emperor", "enforce", "engaged", "enhance", "enquiry",
    "episode", "essence", "estate", "eternal", "ethical", "evident", "examine", "example",
    "excited", "execute", "exhibit", "expense", "explain", "explore", "express", "extract",
    "extreme", "faculty", "failure", "fashion", "feature", "fiction", "fifteen", "fighter",
    "finance", "finding", "fishing", "fitness", "flexible", "floating", "flourish", "focused",
    "forecast", "forever", "formula", "fortune", "forward", "founder", "freedom", "freeze",
    "frequent", "friendly", "frontier", "frozen", "funding", "further", "galaxy", "gallery",
    "gateway", "general", "genetic", "genuine", "gesture", "glimpse", "glorious", "gradual",
    "gravity", "greater", "grocery", "growing", "habitat", "halfway", "handful", "handler",
    "happen", "harbor", "harmony", "harvest", "health", "hearing", "heavily", "helpful",
    "herself", "highway", "himself", "history", "honesty", "horizon", "hostile", "housing",
    "humble", "hunter", "iceberg", "illness", "imagine", "immense", "implant", "implied",
    "impose", "improve", "impulse", "include", "income", "indeed", "indoor", "induce",
    "industry", "infancy", "inferno", "infinite", "influx", "inform", "inject", "injured",
    "inmate", "innocent", "inquiry", "insight", "inspect", "install", "instant", "instead",
    "intact", "intend", "intense", "intent", "interest", "interim", "internal", "interval",
    "intimate", "invade", "invest", "invite", "involve", "isolate", "jointly", "journal",
    "journey", "junior", "justice", "justify", "keenly", "kernel", "kidney", "kingdom",
    "kitchen", "kitten", "knight", "label", "landing", "largest", "lasting", "launch",
    "lawyer", "layout", "leading", "league", "leather", "lecture", "legally", "lending",
    "length", "lesson", "liaison", "liberal", "liberty", "library", "license", "lifting",
    "limited", "listing", "literal", "lively", "living", "longest", "lottery", "loyalty",
    "luggage", "luminous", "luxury", "machine", "madness", "magnetic", "maintain", "majority",
    "manager", "mandate", "mansion", "manual", "marathon", "marble", "margin", "maritime",
    "marker", "market", "massive", "master", "material", "matter", "mature", "maximum",
    "measure", "medical", "medium", "member", "memory", "mental", "mention", "mentor",
    "merchant", "mercury", "merely", "merger", "merit", "message", "method", "midnight",
    "migrant", "mildly", "military", "million", "mineral", "minimal", "minimum", "miracle",
    "mirror", "misery", "mission", "mistake", "mixture", "mobile", "modem", "moderate",
    "modest", "modify", "module", "moisture", "molecule", "monitor", "monopoly", "monster",
    "monthly", "monument", "moral", "moreover", "motion", "mount", "mountain", "movement",
    "multiple", "murmur", "museum", "musical", "mutual", "myself", "mystery", "narrow",
    "nation", "native", "natural", "nature", "nearby", "nearly", "necklace", "negative",
    "neglect", "neither", "nervous", "network", "neutral", "never", "nevertheless", "nominee",
    "nonsense", "normal", "northern", "notable", "notably", "notice", "notion", "nourish",
    "nowhere", "nuclear", "nursery", "nursing", "object", "observe", "obtain", "obvious",
    "occupy", "offense", "officer", "ongoing", "opening", "operate", "opinion", "opposed",
    "optical", "orange", "orbit", "orchestra", "ordered", "organ", "orient", "origin",
    "ornament", "outcome", "outdoor", "outline", "outlook", "output", "outrage", "overall",
    "overlap", "oversee", "palace", "pamphlet", "panacea", "panel", "panic", "parade",
    "parent", "parish", "parking", "parliament", "partial", "partner", "passage", "passion",
    "passive", "pasture", "patent", "patience", "patient", "patrol", "pattern", "payment",
    "peace", "peasant", "peculiar", "penalty", "pending", "penetrate", "pension", "percent",
    "perfect", "perfume", "period", "permit", "person", "persuade", "phrase", "physician",
    "piano", "picture", "pierce", "pilgrim", "pillar", "pilot", "pipeline", "pirate",
    "pistol", "pitch", "planet", "plastic", "plateau", "play", "player", "plead",
    "pleasant", "pledge", "plenty", "plunge", "pocket", "poetry", "point", "poison",
    "police", "policy", "polish", "polite", "poor", "popcorn", "popular", "portable",
    "portal", "portion", "portrait", "portray", "postage", "poster", "potato", "potent",
    "poverty", "powder", "powers", "practical", "praise", "precede", "precise", "predict",
    "prefer", "premier", "premium", "prepare", "present", "preserve", "pressing", "prestige",
    "pretend", "prevent", "preview", "pricing", "primary", "printer", "priority", "prison",
    "privacy", "private", "probable", "problem", "proceed", "process", "produce", "product",
    "profile", "program", "project", "promise", "promote", "prospect", "protect", "protein",
    "protest", "proud", "proven", "provide", "provoke", "prudent", "psychic", "public",
    "publish", "pulse", "pumpkin", "punch", "punctual", "punish", "pupil", "purchase",
    "purely", "pursuit", "puzzle", "pyramid", "qualify", "quality", "quarter", "quick",
    "quiet", "quite", "quiver", "quota", "quote", "rabbit", "racial", "radar", "radical",
    "radius", "rainbow", "random", "rapid", "rarely", "rather", "rating", "reader",
    "readily", "reality", "realize", "reason", "recall", "receipt", "receive", "recent",
    "recipe", "reckon", "reclaim", "recognize", "record", "recover", "recruit", "redemption",
    "reduce", "refer", "reflect", "reform", "refuge", "refusal", "regain", "regard",
    "regime", "region", "register", "regret", "regulate", "reject", "relate", "relax",
    "release", "relief", "relish", "remain", "remark", "remedy", "remind", "remnant",
    "remote", "removal", "render", "renew", "rental", "repair", "repeat", "replace",
    "report", "repose", "rescue", "reserve", "reside", "resign", "resist", "resolve",
    "resort", "rest", "result", "retail", "retain", "retire", "retreat", "return",
    "reveal", "revenue", "reverse", "review", "revise", "revival", "reward", "rhythm",
    "riddle", "rifle", "right", "rigid", "rival", "river", "robin", "robust",
    "rocket", "romance", "roster", "rotate", "rough", "round", "routine", "royal",
    "rubber", "rugged", "ruler", "running", "rural", "sacred", "sadness", "safety",
    "salary", "salmon", "sample", "sanction", "satellite", "satisfy", "sauce", "saving",
    "saying", "scale", "scandal", "scarce", "scatter", "scenario", "schedule", "scholar",
    "school", "science", "scout", "screen", "script", "scrutiny", "seal", "search",
    "season", "second", "secret", "section", "secure", "segment", "select", "senator",
    "senior", "sensor", "sentence", "separate", "sequence", "serial", "serious", "servant",
    "serve", "service", "session", "setting", "settle", "severe", "shadow", "shallow",
    "sharing", "shelter", "shield", "shining", "shipment", "shiver", "shock", "short",
    "shortly", "silence", "silicon", "similar", "sincere", "single", "sister", "sitting",
    "situated", "sketch", "skilled", "slavery", "sleeve", "slender", "slightly", "slowly",
    "smooth", "soccer", "social", "society", "soften", "software", "solar", "soldier",
    "solely", "solemn", "solicit", "solid", "solo", "solution", "somehow", "someone",
    "sonata", "sooner", "sorrow", "sorted", "source", "southern", "sovereign", "spare",
    "spark", "speak", "special", "species", "specify", "speech", "sphere", "spirit",
    "splendid", "sponsor", "sport", "spot", "spray", "spread", "spring", "square",
    "stabilize", "stable", "stadium", "staff", "stage", "stain", "stake", "stance",
    "standard", "standing", "start", "state", "static", "station", "statue", "status",
    "steady", "steal", "steel", "steep", "steering", "stem", "step", "stereo",
    "stern", "steward", "stick", "stiff", "stimulus", "stir", "stitch", "stock",
    "stomach", "stone", "stool", "storage", "storm", "story", "stove", "strange",
    "strategy", "straw", "stream", "street", "strength", "stress", "stretch", "strict",
    "stride", "strike", "string", "strip", "stroke", "strong", "structure", "struggle",
    "studio", "submit", "subtle", "suburb", "succeed", "success", "suffer", "sufficient",
    "suggest", "suit", "summit", "summon", "sunset", "superb", "supplier", "support",
    "supreme", "surface", "surge", "surplus", "survive", "suspect", "suspend", "sustain",
    "swallow", "swamp", "swap", "swift", "switch", "symbol", "symptom", "syndrome",
    "system", "tablet", "tackle", "talent", "target", "tariff", "taste", "tattoo",
    "taxi", "teacher", "temple", "tenant", "tender", "tennis", "tension", "terminal",
    "terrain", "territory", "terror", "testify", "textile", "texture", "theater", "theory",
    "therapy", "thereby", "thermometer", "thirst", "thorough", "thought", "thousand", "thread",
    "threat", "thrill", "thrive", "throat", "through", "thumb", "thunder", "ticket",
    "tide", "tiger", "timber", "timely", "timing", "tissue", "title", "token",
    "tolerance", "tomato", "tonight", "topical", "topple", "torch", "tornado", "torque",
    "torture", "total", "touch", "tough", "tourism", "tourist", "toward", "tower",
    "track", "tractor", "trade", "traffic", "tragedy", "trail", "train", "trait",
    "transaction", "transfer", "transform", "transit", "transmit", "transport", "trap",
    "travel", "tray", "treasure", "treat", "treaty", "tremble", "tremendous", "trend",
    "trial", "tribe", "tribute", "trick", "trigger", "trilogy", "triumph", "troop",
    "trophy", "trouble", "truck", "truly", "trumpet", "trunk", "trust", "trustee",
    "truth", "trying", "tunnel", "turbo", "tutor", "twice", "twin", "twist",
    "typical", "ultimate", "umbrella", "unable", "unaware", "unbroken", "uncertain", "uncle",
    "uncommon", "undergo", "undermine", "understand", "undertake", "uneasy", "unfair", "unfold",
    "unhappy", "uniform", "unique", "united", "unity", "universal", "unknown", "unlikely",
    "unlock", "unusual", "update", "upgrade", "uphold", "upright", "upset", "upward",
    "urban", "urge", "urgent", "useful", "useless", "utility", "utilize", "utmost",
    "vacant", "vacuum", "valid", "valley", "valuable", "value", "valve", "vanish",
    "vapor", "various", "vary", "vast", "vector", "vehicle", "velocity", "vendor",
    "venture", "verbal", "verify", "version", "veto", "viable", "vibrant", "victim",
    "victory", "video", "view", "village", "vintage", "violate", "violent", "virtual",
    "virtue", "virus", "visa", "vision", "visit", "visual", "vital", "vivid",
    "vocal", "vodka", "volcano", "volume", "voluntary", "vortex", "voucher", "voyage",
    "vulnerable", "wage", "wagon", "waist", "wallet", "wander", "warmth", "warning",
    "warrant", "warrior", "wary", "waste", "watch", "water", "waterfall", "wavelength",
    "wealth", "weapon", "wearing", "weather", "weave", "wedding", "weekend", "weight",
    "welcome", "welfare", "western", "whatsoever", "wheat", "wheel", "whenever", "whereas",
    "wherever", "whether", "whisper", "whistle", "whoever", "whole", "whom", "wicked",
    "wide", "widespread", "widow", "width", "wield", "wild", "will", "willing",
    "window", "wine", "wing", "winner", "winter", "wipe", "wire", "wisdom",
    "wise", "wish", "wit", "witch", "withdraw", "within", "without", "witness",
    "wizard", "wonder", "wooden", "wool", "word", "work", "worker", "workshop",
    "world", "worry", "worship", "worth", "wound", "wrap", "wreck", "wrist",
    "writer", "writing", "wrong", "yearly", "yellow", "yield", "young", "youth",
    "zenith", "zero", "zone", "zoo",
];

const MEMORABLE_ADJECTIVES: &[&str] = &[
    "happy", "bright", "swift", "calm", "bold", "cool", "dark", "fast", "gold", "keen",
    "lucky", "brave", "clear", "crisp", "deep", "eager", "fierce", "gentle", "grand", "jolly",
    "lofty", "mellow", "neat", "noble", "proud", "quiet", "rapid", "sharp", "silent", "sunny",
    "vivid", "warm", "zesty", "ample", "brisk", "chill", "cosy", "droll", "flair", "fresh",
    "gleam", "hazel", "jazzy", "lucid", "merry", "nifty", "peppy", "plush", "ruddy", "slick",
    "spry", "sturdy", "suave", "trim", "vital", "witty",
];

const MEMORABLE_NOUNS: &[&str] = &[
    "tiger", "eagle", "panda", "lion", "wolf", "hawk", "bear", "deer", "frog", "swan",
    "dove", "crow", "duck", "rat", "bat", "bee", "fox", "owl", "elk", "ram",
    "eel", "ape", "crab", "dove", "gnu", "jay", "koi", "lynx", "mole", "newt",
    "orca", "puma", "ray", "seal", "slug", "toad", "wren", "boar", "cobra", "crane",
    "gecko", "goose", "heron", "koala", "lemur", "llama", "moose", "otter", "raven", "rhino",
    "robin", "shark", "skunk", "snail", "spider", "steed", "swift", "tapir", "turtle", "viper",
    "whale", "zebra",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_random() {
        let policy = GenerationPolicy {
            length: 32, include_lowercase: true, include_uppercase: true,
            include_digits: true, include_symbols: true, no_ambiguous: false,
            min_numbers: 0, min_symbols: 0, style: PasswordStyle::Random,
        };
        let password = PasswordGenerator::generate(&policy);
        assert_eq!(password.len(), 32);
        assert!(password.chars().any(|c| c.is_ascii_lowercase()));
        assert!(password.chars().any(|c| c.is_ascii_uppercase()));
        assert!(password.chars().any(|c| c.is_ascii_digit()));
        assert!(password.chars().any(|c| !c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_generate_pin() {
        let policy = GenerationPolicy {
            length: 6, ..Default::default()
        };
        // Override style
        let mut p = policy;
        p.style = PasswordStyle::Pin;
        p.length = 6;
        let password = PasswordGenerator::generate(&p);
        assert_eq!(password.len(), 6);
        assert!(password.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_diceware() {
        let policy = GenerationPolicy {
            style: PasswordStyle::Diceware, ..Default::default()
        };
        let password = PasswordGenerator::generate(&policy);
        assert!(!password.is_empty());
        assert!(password.contains('-'));
    }

    #[test]
    fn test_generate_memorable() {
        let policy = GenerationPolicy {
            style: PasswordStyle::Memorable, ..Default::default()
        };
        let password = PasswordGenerator::generate(&policy);
        assert!(!password.is_empty());
        // Memorable format: adj+noun+number
        assert!(password.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_generate_random_no_ambiguous() {
        let policy = GenerationPolicy {
            length: 32, include_lowercase: true, include_uppercase: true,
            include_digits: true, include_symbols: true, no_ambiguous: true,
            min_numbers: 0, min_symbols: 0, style: PasswordStyle::Random,
        };
        let password = PasswordGenerator::generate(&policy);
        assert_eq!(password.len(), 32);
        // Check no ambiguous chars
        let ambiguous = ['1', 'l', 'I', '0', 'O', 'o'];
        for c in password.chars() {
            assert!(!ambiguous.contains(&c));
        }
    }

    #[test]
    fn test_generate_random_uniqueness() {
        let policy = GenerationPolicy {
            length: 16, style: PasswordStyle::Random, ..Default::default()
        };
        let p1 = PasswordGenerator::generate(&policy);
        let p2 = PasswordGenerator::generate(&policy);
        assert_ne!(p1, p2);
    }

    #[test]
    fn test_generate_empty_pool_fallback() {
        let policy = GenerationPolicy {
            length: 8, include_lowercase: false, include_uppercase: false,
            include_digits: false, include_symbols: false, no_ambiguous: false,
            min_numbers: 0, min_symbols: 0, style: PasswordStyle::Random,
        };
        let password = PasswordGenerator::generate(&policy);
        assert_eq!(password.len(), 8);
    }
}
