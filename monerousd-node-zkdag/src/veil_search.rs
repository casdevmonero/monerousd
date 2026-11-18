// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ SEARCHING THE VEIL (user 2026-11-12: "the sovereign browser is supposed to be a google equivalent browser in which
//! all published sites appear on and can be searched up by name" · "if people search 'buy cars' then car selling sites
//! should pop up and so on").
//!
//! WHAT IS SEARCHED. Every site the chain says is published at a name (the chain directory's names and the site
//! registry's publishes: [`published`]), each read by what its OWN FRONT PAGE says: its title, its description and
//! keywords, its headings and its text ([`Card::of_html`]), taken from the site's `index.html` in this node's store, so
//! from bytes this node checked against the root the chain anchors. Nothing the publisher states beside the site is
//! read: what a person finds is what the page shows (a publisher cannot list a site under words its page does not say
//! except by putting them on the page, where every reader sees them).
//!
//! WHERE IT RUNS. On the person's OWN node, over that node's own state and store. A search sends nothing to anyone, so
//! no node, holder or observer learns what was searched for; the query is matched in this process and never logged,
//! stored or sent (DIGITAL CASH: no which-item query leaves the machine). BORROWED: the inverted-index scoring of a
//! classic search engine (term weights per field, as in BM25F), run over a small per-site card instead of a crawl.
//!
//! RANKING ([`score`]). The query is cut into words, common words dropped, each word stemmed (cars → car) and widened
//! by a small table of words that mean the same thing to a person shopping or looking (buy ~ shop ~ sale ~ sell). A
//! word found in the site's name counts most, then its title, its keywords, its headings and description, then its
//! text; a site that matches every word of the query is ranked above one that matches some. The exact name a person
//! typed is always first.
//!
//! WHAT PROTECTS IT (AI RESISTANT, §2): (b) ordinary code. Search moves no value and decides nothing on the chain; a
//! site can only rank for words its own checked page carries.
//!
//! SCALE (SAFE AT SCALE, §2). Per query: one pass over the published sites, each scored against its cached card
//! (constant work per site). RAM: one card of at most [`CARD_TEXT`] bytes of text per published site this node holds
//! the front page of, a cache rebuilt from the store and pruned to the sites published now; the store it reads is the
//! constant-size site store. Bytes, messages and rounds on the network: none.

use crate::directory::Directory;
use crate::hash::Hash32;
use crate::site::SiteRegistry;
use crate::veil::{resolve_mud, MudSite, SiteHost, MUD_SUFFIX};
use std::collections::{HashMap, HashSet};

/// How much of a front page is read to make its card.
pub const CARD_READ: u64 = 128 * 1024;
/// How much of a page's text a card keeps.
pub const CARD_TEXT: usize = 6000;

/// Every site the chain says is published at a name, each the one its name's OWNER published, in name order.
#[must_use]
pub fn published(names: &Directory, sites: &SiteRegistry) -> Vec<MudSite> {
    names.name_spellings().into_iter().filter_map(|n| resolve_mud(names, sites, &format!("{n}{MUD_SUFFIX}"))).collect()
}

/// What a site's front page says, as search reads it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Card {
    pub title: String,
    pub description: String,
    pub keywords: String,
    pub headings: String,
    pub text: String,
}

/// A card cut into the stemmed words of each of its fields.
#[derive(Clone, Debug, Default)]
pub struct Indexed {
    pub card: Card,
    title: HashSet<String>,
    keywords: HashSet<String>,
    headings: HashSet<String>,
    description: HashSet<String>,
    text: HashMap<String, u32>,
}

impl Indexed {
    #[must_use]
    pub fn of(card: Card) -> Indexed {
        let set = |s: &str| words(s).collect::<HashSet<String>>();
        let mut text = HashMap::new();
        for w in words(&card.text) {
            *text.entry(w).or_insert(0) += 1;
        }
        Indexed { title: set(&card.title), keywords: set(&card.keywords), headings: set(&card.headings), description: set(&card.description), text, card }
    }
}

fn decode_entities(s: &str) -> String {
    s.replace("&nbsp;", " ").replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'").replace("&apos;", "'")
}

fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// `s` with every `<tag …>…</tag>` block of `tag` taken out (scripts and styles are not what a page says).
fn drop_blocks(s: &str, tag: &str) -> String {
    let lower = s.to_ascii_lowercase();
    let (open, close) = (format!("<{tag}"), format!("</{tag}"));
    let mut out = String::with_capacity(s.len());
    let mut at = 0;
    while let Some(i) = lower[at..].find(&open).map(|i| at + i) {
        out.push_str(&s[at..i]);
        match lower[i..].find(&close).map(|j| i + j) {
            Some(j) => at = lower[j..].find('>').map_or(s.len(), |k| j + k + 1),
            None => {
                at = s.len();
                break;
            }
        }
    }
    out.push_str(&s[at.min(s.len())..]);
    out
}

/// The text inside every `<tag>…</tag>` of `tag`, tags inside it removed.
fn inner_of(s: &str, lower: &str, tag: &str) -> Vec<String> {
    let (open, close) = (format!("<{tag}"), format!("</{tag}>"));
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(i) = lower[at..].find(&open).map(|i| at + i) {
        // `<h1` must not match `<h10` or `<header`: the next byte closes the tag name
        let after = lower.as_bytes().get(i + open.len()).copied().unwrap_or(b'>');
        let Some(start) = lower[i..].find('>').map(|k| i + k + 1) else { break };
        if !(after == b'>' || after.is_ascii_whitespace() || after == b'/') {
            at = start;
            continue;
        }
        let end = lower[start..].find(&close).map_or(s.len(), |k| start + k);
        out.push(squash(&decode_entities(&strip_tags(&s[start..end]))));
        at = end;
    }
    out
}

fn strip_tags(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' if in_tag => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out
}

/// The value of attribute `name` inside one tag's text (`<meta name="x" content="y">`), quoted either way.
fn attr(tag: &str, lower: &str, name: &str) -> Option<String> {
    let mut from = 0;
    while let Some(i) = lower[from..].find(name).map(|i| from + i) {
        let before_ok = i == 0 || !lower.as_bytes()[i - 1].is_ascii_alphanumeric();
        let rest = lower[i + name.len()..].trim_start();
        if before_ok && rest.starts_with('=') {
            let skip = lower.len() - rest.len() + 1;
            let value_lower = lower[skip..].trim_start();
            let at = lower.len() - value_lower.len();
            let q = tag[at..].chars().next()?;
            if q == '"' || q == '\'' {
                let body = &tag[at + 1..];
                return Some(body[..body.find(q)?].to_string());
            }
            return Some(tag[at..].split(|c: char| c.is_whitespace() || c == '>').next()?.to_string());
        }
        from = i + name.len();
    }
    None
}

impl Card {
    /// Read a front page: its `<title>`, its description (`<meta name="description">`, or the Open Graph one) and
    /// keywords, its `<h1>` to `<h3>` headings, and its visible text without scripts or styles.
    #[must_use]
    pub fn of_html(html: &[u8]) -> Card {
        let raw = String::from_utf8_lossy(html);
        let page = drop_blocks(&drop_blocks(&drop_blocks(&raw, "script"), "style"), "noscript");
        let page = {
            // comments
            let mut out = String::with_capacity(page.len());
            let mut rest = page.as_str();
            while let Some(i) = rest.find("<!--") {
                out.push_str(&rest[..i]);
                rest = rest[i..].find("-->").map_or("", |j| &rest[i + j + 3..]);
            }
            out.push_str(rest);
            out
        };
        let lower = page.to_ascii_lowercase();
        let title = inner_of(&page, &lower, "title").into_iter().next().unwrap_or_default();
        let (mut description, mut keywords) = (String::new(), String::new());
        let mut at = 0;
        while let Some(i) = lower[at..].find("<meta").map(|i| at + i) {
            let end = lower[i..].find('>').map_or(lower.len(), |k| i + k + 1);
            let (tag, tag_lower) = (&page[i..end], &lower[i..end]);
            let named = attr(tag, tag_lower, "name").or_else(|| attr(tag, tag_lower, "property")).unwrap_or_default().to_ascii_lowercase();
            let content = attr(tag, tag_lower, "content").map(|c| squash(&decode_entities(&c))).unwrap_or_default();
            match named.as_str() {
                "description" | "og:description" if description.is_empty() => description = content,
                "keywords" => keywords = content,
                _ => {}
            }
            at = end;
        }
        let headings = ["h1", "h2", "h3"].iter().flat_map(|h| inner_of(&page, &lower, h)).collect::<Vec<_>>().join(" · ");
        let body_at = lower.find("<body").unwrap_or(0);
        let mut text = squash(&decode_entities(&strip_tags(&page[body_at..])));
        if text.len() > CARD_TEXT {
            let mut cut = CARD_TEXT;
            while !text.is_char_boundary(cut) {
                cut -= 1;
            }
            text.truncate(cut);
        }
        let clip = |s: String, n: usize| s.chars().take(n).collect::<String>();
        Card { title: clip(title, 200), description: clip(description, 400), keywords: clip(keywords, 400), headings: clip(headings, 800), text }
    }

    /// What a result shows under its title: the description, or the start of the page's text.
    #[must_use]
    pub fn snippet(&self) -> String {
        let from = if self.description.is_empty() { &self.text } else { &self.description };
        let s: String = from.chars().take(180).collect();
        if from.chars().count() > 180 { format!("{}…", s.trim_end()) } else { s }
    }
}

const STOP: &[&str] = &[
    "a", "an", "the", "and", "or", "of", "to", "in", "on", "at", "for", "with", "by", "from", "is", "are", "be", "i", "me", "my", "we", "our", "you",
    "your", "it", "its", "this", "that", "near", "best", "good", "top", "how", "what", "where", "who", "find", "get", "some", "any", "online", "site",
    "website", "page", "mud",
];

/// Words a person means alike, by their stems: a query word finds a page that says any word of its group.
const ALIKE: &[&[&str]] = &[
    &["buy", "shop", "store", "sale", "sell", "seller", "purchase", "price", "deal", "order", "market", "marketplace", "dealer", "dealership"],
    &["car", "auto", "automobile", "vehicle", "truck", "suv", "motor"],
    &["food", "restaurant", "eat", "meal", "dinner", "lunch", "cafe", "recipe", "cook", "kitchen"],
    &["house", "home", "apartment", "rent", "rental", "realestate", "property", "flat"],
    &["job", "career", "hire", "hiring", "work", "employment", "vacancy"],
    &["news", "blog", "article", "post", "journal", "story"],
    &["clothes", "clothing", "fashion", "wear", "shirt", "dress", "shoe", "apparel"],
    &["phone", "mobile", "smartphone", "cellphone"],
    &["computer", "laptop", "pc", "tech", "electronic", "gadget"],
    &["music", "song", "album", "band", "audio"],
    &["game", "gaming", "play"],
    &["art", "artist", "gallery", "painting", "nft", "design", "portfolio"],
    &["coin", "crypto", "bitcoin", "monero", "token", "defi", "swap", "exchange"],
    &["learn", "course", "class", "school", "lesson", "tutorial", "education"],
    &["doctor", "health", "clinic", "medical", "medicine"],
    &["travel", "trip", "hotel", "flight", "vacation"],
];

/// A word's stem: lower case, plurals and the commonest endings cut, so "cars", "selling" and "shops" meet "car",
/// "sell" and "shop".
#[must_use]
pub fn stem(word: &str) -> String {
    let w = word.to_lowercase();
    let n = w.chars().count();
    // "-es" is a plural ending only after s, x, z, ch and sh ("boxes", "dishes"); else it is "-e" + "s" ("vehicles")
    let es_plural = ["ses", "xes", "zes", "ches", "shes"].iter().any(|e| w.ends_with(e));
    for (end, keep) in [("ies", "y"), ("ing", ""), ("ers", "er"), ("es", ""), ("s", "")] {
        if end == "es" && !es_plural {
            continue;
        }
        if n > end.len() + 2 && w.ends_with(end) && !w.ends_with("ss") {
            let base = format!("{}{keep}", &w[..w.len() - end.len()]);
            // "selling" → "sell", "shopping" → "shop": a doubled last letter left by -ing
            let b = base.as_bytes();
            if end == "ing" && b.len() > 3 && b[b.len() - 1] == b[b.len() - 2] && b[b.len() - 1] != b'l' && b[b.len() - 1] != b's' {
                return base[..base.len() - 1].to_string();
            }
            return base;
        }
    }
    w
}

fn words(s: &str) -> impl Iterator<Item = String> + '_ {
    s.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).map(stem)
}

/// The query as groups of stems: one group per meaningful word, each word widened by the words alike to it.
#[must_use]
pub fn query_terms(query: &str) -> Vec<Vec<String>> {
    let q = query.trim().trim_start_matches('@').to_lowercase();
    let q = q.strip_suffix(MUD_SUFFIX).unwrap_or(&q);
    let mut out: Vec<Vec<String>> = Vec::new();
    for w in q.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty() && !STOP.contains(w)) {
        let s = stem(w);
        let mut group = vec![s.clone()];
        for alike in ALIKE {
            if alike.iter().any(|a| stem(a) == s) {
                group.extend(alike.iter().map(|a| stem(a)).filter(|a| *a != s));
            }
        }
        if !out.iter().any(|g| g[0] == s) {
            out.push(group);
        }
    }
    out
}

/// How well a site answers the query, and whether it matches EVERY word of it: 0 when it matches none. The words
/// themselves weigh more than the words alike to them; the exact name a person typed is always first.
#[must_use]
pub fn score(name: &str, card: Option<&Indexed>, terms: &[Vec<String>], typed: &str) -> (u32, bool) {
    let typed = typed.trim().trim_start_matches('@').to_lowercase();
    let typed = typed.strip_suffix(MUD_SUFFIX).unwrap_or(&typed).replace(' ', "");
    let exact = !typed.is_empty() && name == typed;
    let mut total = 0u32;
    let mut matched = 0usize;
    for group in terms {
        let mut best = 0u32;
        for (k, w) in group.iter().enumerate() {
            let weight = |base: u32| if k == 0 { base * 2 } else { base };
            let mut hit = 0u32;
            if w.len() >= 2 && name.contains(w.as_str()) {
                hit = hit.max(weight(8));
            }
            if let Some(c) = card {
                if c.title.contains(w) {
                    hit = hit.max(weight(6));
                }
                if c.keywords.contains(w) {
                    hit = hit.max(weight(5));
                }
                if c.headings.contains(w) {
                    hit = hit.max(weight(4));
                }
                if c.description.contains(w) {
                    hit = hit.max(weight(4));
                }
                if let Some(n) = c.text.get(w) {
                    hit = hit.max(weight(1 + (*n).min(4)));
                }
            }
            best = best.max(hit);
        }
        if best > 0 {
            matched += 1;
            total += best;
        }
    }
    let all = matched == terms.len() && matched > 0;
    if exact {
        return (10_000 + total, true);
    }
    if matched == 0 {
        return (0, false);
    }
    if all {
        total *= 2;
    }
    (total, all)
}

/// One search result.
#[derive(Clone, Debug)]
pub struct Hit {
    pub site: MudSite,
    pub title: String,
    pub snippet: String,
    pub score: u32,
}

/// Cards by site root: a cache of what this node read from its own store, rebuilt at need, pruned to the sites
/// published now. A root's bytes never change, so a card is never stale.
static CARDS: std::sync::Mutex<Option<HashMap<Hash32, Indexed>>> = std::sync::Mutex::new(None);

/// The card of the site `root` binds, read from `host` once and kept: `None` while this node lacks its front page.
fn card(host: &mut SiteHost, root: &Hash32, cache: &mut HashMap<Hash32, Indexed>) -> Option<Indexed> {
    if let Some(c) = cache.get(root) {
        return Some(c.clone());
    }
    let (start, len) = host.locate(root, "index.html").ok()??;
    let bytes = host.read(root, start, len.min(CARD_READ)).ok()?;
    let indexed = Indexed::of(Card::of_html(&bytes));
    cache.insert(*root, indexed.clone());
    Some(indexed)
}

/// SEARCH the published `sites` for `query`, best first. With no query, every site in name order. `host` is this
/// node's site store, where each front page is read (without one, sites are found by name alone). Like a web search
/// engine, a query of several words lists the sites that match ALL of them; only when no site does are the sites that
/// match some of them listed.
#[must_use]
pub fn search(sites: Vec<MudSite>, mut host: Option<&mut SiteHost>, query: &str) -> Vec<Hit> {
    let terms = query_terms(query);
    let mut guard = CARDS.lock().unwrap_or_else(|e| e.into_inner());
    let cache = guard.get_or_insert_with(HashMap::new);
    // PRODUCTION-SCALE-REVIEWED: the cache holds one card per site published now and is pruned to them here.
    if cache.len() > sites.len() {
        let live: HashSet<Hash32> = sites.iter().map(|s| s.publish.manifest_root).collect();
        cache.retain(|r, _| live.contains(r));
    }
    let everything = terms.is_empty() && query.trim().is_empty();
    let scored: Vec<(MudSite, Option<Indexed>, u32, bool)> = sites
        .into_iter()
        .map(|site| {
            let root = site.publish.manifest_root;
            let c = host.as_deref_mut().and_then(|h| card(h, &root, cache));
            let (s, all) = if everything { (1, true) } else { score(&site.name, c.as_ref(), &terms, query) };
            (site, c, s, all)
        })
        .collect();
    let any_all = scored.iter().any(|x| x.2 > 0 && x.3);
    let mut hits: Vec<Hit> = scored
        .into_iter()
        .filter_map(|(site, c, s, all)| {
            (s > 0 && (all || !any_all)).then(|| Hit {
                title: c.as_ref().map(|c| c.card.title.clone()).filter(|t| !t.is_empty()).unwrap_or_else(|| format!("{}{MUD_SUFFIX}", site.name)),
                snippet: c.as_ref().map(|c| c.card.snippet()).unwrap_or_default(),
                site,
                score: s,
            })
        })
        .collect();
    hits.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.site.name.cmp(&b.site.name)));
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    const CARS: &str = r#"<!doctype html><html><head><title>Ada's Autos — used cars for sale</title>
        <meta name="description" content="Quality used cars &amp; trucks, sold with a full history.">
        <meta name='keywords' content='cars, trucks, dealer'><style>h1{color:red}</style><script>var buy='x'</script></head>
        <body><header><h1>Find your next car</h1></header><p>We sell over 200 vehicles a month.</p><!-- buy buy buy --></body></html>"#;
    const BAKERY: &str = r#"<html><head><title>Rosie's Bakery</title><meta name="description" content="Fresh bread every morning"></head>
        <body><h1>Bread and cakes</h1><p>Order a birthday cake online.</p></body></html>"#;
    const NEWS: &str = "<html><head><title>Veil Daily</title></head><body><h2>Car prices rise</h2><p>A story about the car market.</p></body></html>";

    #[test]
    fn a_front_page_is_read_for_what_it_says_and_not_for_its_scripts() {
        let c = Card::of_html(CARS.as_bytes());
        assert_eq!(c.title, "Ada's Autos — used cars for sale");
        assert_eq!(c.description, "Quality used cars & trucks, sold with a full history.");
        assert_eq!(c.keywords, "cars, trucks, dealer");
        assert_eq!(c.headings, "Find your next car");
        assert!(c.text.contains("We sell over 200 vehicles"));
        assert!(!c.text.contains("var buy") && !c.text.contains("color:red") && !c.text.contains("buy buy"), "a script, a style or a comment was read as text");
        assert_eq!(c.snippet(), "Quality used cars & trucks, sold with a full history.");
        assert_eq!(Card::of_html(b"no html at all, just words").text, "no html at all, just words");
        assert_eq!(Card::of_html(b"<html><head><title>unclosed").title, "unclosed");
    }

    #[test]
    fn buy_cars_finds_the_car_seller_first_and_never_the_bakery() {
        let (cars, bakery, news) = (Indexed::of(Card::of_html(CARS.as_bytes())), Indexed::of(Card::of_html(BAKERY.as_bytes())), Indexed::of(Card::of_html(NEWS.as_bytes())));
        let q = query_terms("buy cars");
        assert_eq!(q.len(), 2);
        let (sc, sb, sn) = (score("adasautos", Some(&cars), &q, "buy cars"), score("rosies", Some(&bakery), &q, "buy cars"), score("veildaily", Some(&news), &q, "buy cars"));
        assert!(sc.1 && sc.0 > sn.0 && sn.0 > 0, "the car seller {sc:?} must rank above a page that only talks about cars {sn:?}");
        assert!(!sb.1, "a bakery matched every word of 'buy cars'");
        // words alike: "shop for vehicles" still finds the car seller
        assert!(score("adasautos", Some(&cars), &query_terms("shop for vehicles"), "shop for vehicles").1);
        assert!(score("rosies", Some(&bakery), &query_terms("cake"), "cake").1);
        // the name a person typed is first whatever its page says
        assert!(score("rosies", Some(&bakery), &query_terms("rosies"), "rosies").0 > score("adasautos", Some(&cars), &query_terms("rosies"), "rosies").0);
        assert!(score("rosies", None, &query_terms("rosies.mud"), "rosies.mud").0 >= 10_000);
        // only stop words: nothing to match on
        assert!(query_terms("the best of").is_empty());
    }

    #[test]
    fn search_lists_every_published_site_by_name_and_only_what_each_names_owner_published() {
        let mut names = Directory::new();
        let mut sites = SiteRegistry::new();
        let claim = |key: &str, owner_address: &str| crate::directory::DirEntry {
            kind: crate::directory::KIND_NAME,
            key: key.to_string(),
            address: owner_address.to_string(),
            name: String::new(),
            topic: String::new(),
            pubkey: Vec::new(),
            sig: Vec::new(),
            pic: None,
        };
        let mut register = |key: &str, owner: [u8; 32]| {
            let e = claim(key, &format!("addr-{key}"));
            assert!(names.apply_entry(&e, owner));
            names.fold_applied(&e);
        };
        let (flame, flamenco, campfire, quiet, mallory) = ([1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [9u8; 32]);
        register("flame", flame);
        register("flamenco", flamenco);
        register("campfire", campfire);
        register("quiet", quiet);
        for (owner, n) in [(flame, "flame"), (flamenco, "flamenco"), (campfire, "campfire")] {
            sites.adopt(crate::site::SitePublish::new(owner, n, 1, Hash32::hash(n.as_bytes())));
        }
        // a site published under a name by a key that does not own it is not that name's site, and is not listed
        sites.adopt(crate::site::SitePublish::new(mallory, "quiet", 1, Hash32::hash(b"not quiet's")));
        let listed = |q: &str| crate::veil_search::search(crate::veil_search::published(&names, &sites), None, q).into_iter().map(|h| h.site.name).collect::<Vec<_>>();
        assert_eq!(listed(""), ["campfire", "flame", "flamenco"], "every published site, and only those");
        assert_eq!(listed("flame"), ["flame", "flamenco"], "the exact name first");
        assert_eq!(listed("FLAME.mud"), ["flame", "flamenco"], "a typed address is the same search");
        assert_eq!(listed("fire"), ["campfire"]);
        assert_eq!(listed("am"), ["campfire", "flame", "flamenco"]);
        assert!(listed("quiet").is_empty(), "⛔ a site its name's owner never published was listed");
        assert!(listed("nobody").is_empty());
        // a newer version is what the listing shows
        sites.adopt(crate::site::SitePublish::new(flame, "flame", 2, Hash32::hash(b"v2")));
        assert_eq!(crate::veil_search::search(crate::veil_search::published(&names, &sites), None, "flame")[0].site.publish.version, 2);
    }

    #[test]
    fn stems_meet_their_words() {
        for (a, b) in [("cars", "car"), ("selling", "sell"), ("shops", "shop"), ("shopping", "shop"), ("bakeries", "bakery"), ("dealers", "dealer"), ("glass", "glass"), ("bus", "bus"), ("vehicles", "vehicle"), ("boxes", "box"), ("prices", "price"), ("sales", "sale")] {
            assert_eq!(stem(a), stem(b), "{a} and {b}");
        }
    }
}
