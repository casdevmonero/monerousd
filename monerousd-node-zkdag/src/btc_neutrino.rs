// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐ §22 6 — THE BUNDLED BITCOIN WATCHER (docs/BRIDGE-USDM-PRIVACY-SPEC-20261024.md §22 6): a BIP 157/158 light client that
//! every validator runs inside the node, over the node's own Tor, with nothing to install.
//!
//! It replaces the explorer read: an explorer was trusted for each answer and LEARNED which addresses the bridge watches. Here:
//! - headers are followed from a release checkpoint by Bitcoin's own rules (`btc_filter::HeaderFollower`: proof of work, the
//!   difficulty each height must carry, median time, most work wins);
//! - every block's FILTER HEADER is taken only when ≥ 3 distinct filter peers report the same one and none another
//!   (`btc_filter::agree`); a filter counts only when its hash is the agreed one;
//! - a block is fetched only when its filter matches a watched script (a deposit to it, or a spend of one), and its
//!   transactions count only when their merkle root is the one in the proof-of-work-checked header;
//! - so no peer can invent a deposit (it would need the work), hide one from three agreeing peers, or learn which scripts are
//!   watched (filters are fetched for every block).
//!
//! The state is constant per watched address: the follower's one-day ring, the agreed filter tip, and each OPEN swap's coins
//! (`Watch::unwatch` drops a settled swap's). The driver ([`sweep`]) runs on the deposit watcher's own thread.
//!
//! cons: ≈ 22 KB per block of filter + filter header over onion, per validator; a deposit funded by a TAPROOT KEY-PATH input
//! does not reveal its sender's script (its key never appears on the spend), so the wallet's refusal to pay a cash-out back to
//! the deposit's sender (§BR-1) cannot name that one sender — an operator's own Bitcoin Core (`MONEROUSD_BTC_RPC_URL`) still
//! reads every prevout.
//!
//! CLASSICAL-BRIDGE-ENDPOINT: a FOREIGN chain's data, read-only — no key, no signature.
//! DIGITAL-CASH-PRIVACY-REVIEWED: onion-only, no address or script ever leaves the node.

use std::collections::BTreeMap;

use crate::btc_filter::{agree, header_hash, Agreement, Checkpoint, HeaderFollower, Params};
use crate::btc_p2p::{self as p2p, Tx};

/// A display-order hash as its internal bytes, at compile time.
const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        let hi = nib(b[2 * i]);
        let lo = nib(b[2 * i + 1]);
        out[31 - i] = (hi << 4) | lo;
        i += 1;
    }
    out
}
const fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => 0,
    }
}

/// MAINNET: block 973727 (the last of its difficulty period), its period's first block 971712, and the eleven
/// headers ending at it — read from a public explorer on 2026-10-30 and re-verified by `checkpoint_headers_verify`.
pub const CHECKPOINT_MAINNET: Checkpoint = Checkpoint {
    hash: hex32("0000000000000000000132b722697381ee70f3c565ed8c2168ef68d54e3b4f04"),
    height: 973727,
    bits: 0x17020093,
    period_first_time: 1792154251,
    period_bits: 0x17020093,
    times: [1793293434, 1793293525, 1793293826, 1793294772, 1793295289, 1793295403, 1793295747, 1793296448, 1793296899, 1793297271, 1793300370],
};
/// The headers behind [`CHECKPOINT_MAINNET`]: its period's first, then the eleven ending at it (display-order hashes).
pub const CHECKPOINT_MAINNET_HEADERS: &[(u32, &str, &str)] = &[
    (971712, "00000000000000000000c185f0906690a08d62d6fe842682a888d5560217e467", "006005202e5ea9d74cd63c1fb65514e47c38f2a4767ad8d6ae51000000000000000000003d63f20e90eb3b43e72ea91858f41d1d92103442acfa6106400e04e08f4d94df8b1ad26a930002176d7224e8"),
    (973717, "0000000000000000000025cfebc8f918f2e147c25d711481d61f330e1c427d91", "00006125c1fc8e3dd536b8c29a3d6e85fb109df52745ca64babb00000000000000000000c6a9d51c936c64a6f89e64b22b56311c584f3fc1e6ce68bcca7c5d0e8565c7247a7ce36a93000217efa81022"),
    (973718, "00000000000000000001a7c5dc18ac78aee6a9731ff09de01b8828e60e24ea7d", "00601120917d421c0e331fd68114715dc247e1f218f9c8ebcf25000000000000000000002e88e0bd4d725e0379e924535759f902c40f256a910d261ade45ebf8af584e91d57ce36a9300021758ec3520"),
    (973719, "00000000000000000000ae55a567a889b3031162e8fa8e964e1e342a7ba63e74", "00a02d217dea240ee628881be09df01f73a9e6ae78ac18dcc5a70100000000000000000084db89f8a36c1a3a27b2447cc6fb9c16445091e48e34d78d883c307905b757f3027ee36a93000217aee98476"),
    (973720, "00000000000000000000065af0b13cfccacaa4bb60737682021301887697856a", "00e00020743ea67b2a341e4e968efae8621103b389a867a555ae000000000000000000002af10724d109d49152cbf3d36c1a36662b49da457807fc6b08ee338d30a917ecb481e36a930002174608f504"),
    (973721, "0000000000000000000063e9360d95ebb75feed2c08940929aa4dac4af2107de", "0000c2306a8597768801130282767360bba4cacafc3cb1f05a06000000000000000000001b0f8cab8288c7cd290a9a5eff19c8a08a64d88240a506f8e68711f609f30eecb983e36a930002177762eb57"),
    (973722, "000000000000000000006806cef33ce79ebb1dab1d639fb17c195a9c40fa08de", "00e0cc26de0721afc4daa49a924089c0d2ee5fb7eb950d36e96300000000000000000000818c36a45f44217f2d7712c76b9f7217e3e813f3f37ceced47d14c553d8269b92b84e36a9300021757e11c51"),
    (973723, "00000000000000000000870a056634b7a80342812dcb5de7126ef42d79d23836", "0000ff3fde08fa409c5a197cb19f631dab1dbb9ee73cf3ce0668000000000000000000007c9f20da96bf22a16872968510b8e0d3eccb94d18bcb14bd23bf9e4a008369ab8385e36a9300021708f6c358"),
    (973724, "00000000000000000000ca9930aee5721654fb86f76c4eefce57ad3af9d07909", "00e0832b3638d2792df46e12e75dcb2d814203a8b73466050a870000000000000000000073c30179c53cdf582d14a05dadaa29e58f41bfdaab1f34112f1aca46fad14c994088e36a9300021796714e9d"),
    (973725, "00000000000000000001e58d1792553996abdb5f72f25cfa6caef5a11120fcd1", "0000ff3f0979d0f93aad57ceef4e6cf786fb541672e5ae3099ca00000000000000000000ed9e771233f74be6df04a2584bade9d47f3a753560faba26571f30ef24509cca038ae36a930002174730be6b"),
    (973726, "00000000000000000001ff87403e4c8128c4a31251cd8a5d1fb92baa1aaaf9f3", "0000d032d1fc2011a1f5ae6cfa5cf2725fdbab96395592178de50100000000000000000046564a25bbdccb09f6ccf6c79385e81eb66cef03afce58f1814ef437696fa734778be36a930002171f48f42e"),
    (973727, "0000000000000000000132b722697381ee70f3c565ed8c2168ef68d54e3b4f04", "00a04b20f3f9aa1aaa2bb91f5d8acd5112a3c428814c3e4087ff0100000000000000000042ab8f9c176bd1993227e826305521f4c23f96b9dfb66354b08bab9f8a004d309297e36a9300021765ed2b3c"),
];
/// TESTNET4: block 157247 (the last of its difficulty period), its period's first block 155232, and the eleven
/// headers ending at it — read from a public explorer on 2026-10-30 and re-verified by `checkpoint_headers_verify`.
pub const CHECKPOINT_TESTNET4: Checkpoint = Checkpoint {
    hash: hex32("0000000000c370a0a97e584d0dc0bd2547da26f7e52028c69ee17367ae9d3e78"),
    height: 157247,
    bits: 0x1d00ffff,
    period_first_time: 1791203299,
    period_bits: 0x19037e43,
    times: [1792626177, 1792627378, 1792628579, 1792629780, 1792630981, 1792632182, 1792633383, 1792634584, 1792635785, 1792636986, 1792638187],
};
/// The headers behind [`CHECKPOINT_TESTNET4`]: its period's first, then the eleven ending at it (display-order hashes).
pub const CHECKPOINT_TESTNET4_HEADERS: &[(u32, &str, &str)] = &[
    (155232, "0000000000000002314dc5b90175408b22d2c80dfe99979629b40e572d40345b", "00c01133a4b225a064922585bd9db58ad1cb7127031c8ba15252c0db7a31cc00000000007f6bf7535d4eb0882eb99466ccacdc6f6848c61d4936aec2e67c75e233f7c363e397c36a437e0319e11e4279"),
    (157237, "00000000008f578ca5a4649de47a6692327ec9bc269acaaaeee786cfdb27e047", "00e051201335b081ac93601afb78c6d24fa1b48fdac4130e392f29020382e40000000000bccb63b2187ca8c444ff0d884d176bab49614c0ea3a29efb0b7357ee8fb4d8bd014ed96affff001d98012995"),
    (157238, "0000000000a13c87d60690fd88048d0e593bf44e964596251acb6abfe836f5a2", "0060982447e027dbcf86e7eeaaca9a26bcc97e3292667ae49d64a4a58c578f0000000000fc6b32ad7c8b923b7356850fa1d5ba0cc4c3bb6db653947921a591bf93fbaeacb252d96affff001d4001c2e4"),
    (157239, "0000000000f990142a7e8c273939003b9766a6787ba5fa6206cde592b6c67a16", "0040ff22a2f536e8bf6acb1a259645964ef43b590e8d0488fd9006d6873ca10000000000aeab9ac5261657cde14173d82ab31d7e0f8cf878c600559cf8742a8693516dea6357d96affff001d8a01dabf"),
    (157240, "0000000000dc2792181c5bd2ba9c379e545b8573237bf70023350628f291a11a", "00808c24167ac6b692e5cd0662faa57b78a666973b003939278c7e2a1490f900000000009b0d1d46109292f859c28aafef3ee3717d9270e24ad37d27bbbd0f4a7e24007b145cd96affff001de80254e5"),
    (157241, "0000000000eb39bc19747cdb96589c43d6415477417d876e9a1300f336f89c62", "00c010221aa191f22806352300f77b2373855b549e379cbad25b1c189227dc0000000000c6ad73e3c87a0b1964bec9b12ec0f787f9eacace3ddfa77152f6855a578b1a17c560d96affff001d560140fe"),
    (157242, "00000000000455d62e92ea09305367e91ed408d5eb84bcf107ed2ba203e1803f", "00603a23629cf836f300139a6e877d41775441d6439c5896db7c7419bc39eb00000000006dab3be10de9ddb6acbbfd40399aa41387287b8e4d48a925407b105d6ccc26ce7665d96affff001dbe016957"),
    (157243, "000000000071f1e6aa825e5796ecef3ec4ec7885ee2147b1b4ac79bd264dfeb0", "0020b4203f80e103a22bed07f1bc84ebd508d41ee967533009ea922ed655040000000000f9c19c6883d5535f05f73cbe54660465514ceb366b9051ca6e748104172db604276ad96affff001d16021784"),
    (157244, "00000000001ba8bb127cfd45492816d1e4479a918dfb36b6e5aacc59ea83776b", "00205d21b0fe4d26bd79acb4b14721ee8578ecc43eefec96575e82aae6f1710000000000f8252713dc7825ed040250c45fecc790136041f84d95d6b7479d7ebd797ba62cd86ed96affff001d8201f01b"),
    (157245, "0000000000b94727a3dd9aed273bc517237630f6d4d716ddb60425cc62d45e66", "0020db226b7783ea59ccaae5b636fb8d919a47e4d116284945fd7c12bba81b00000000001f794ed70197bb4ebc67e09e30a40b67d3b65dbc690c7971709623bcc91ea6a68973d96affff001de20005c5"),
    (157246, "000000000073064e17907dcde4fa841b14c222af3bdd4bdf197f2150a16fec6a", "00004922665ed462cc2504b6dd16d7d4f630762317c53b27ed9adda32747b90000000000fda472f77d1888ee3ceb40414e1eb3ecd873a0df9fb74622b073bc6223fb7cb53a78d96affff001d6801082c"),
    (157247, "0000000000c370a0a97e584d0dc0bd2547da26f7e52028c69ee17367ae9d3e78", "00404f216aec6fa150217f19df4bdd3baf22c2141b84fae4cd7d90174e0673000000000043eb25c65c6c5354b4bb7024fad59867cda8a898905fe1a7bf60de7238972100eb7cd96affff001d3e01d7ad"),
];

/// Bitcoin onion peers (Tor v3), from Bitcoin Core's own `contrib/seeds/nodes_main.txt` (read 2026-10-30). A watcher keeps
/// only those whose `version` advertises compact filters and witness blocks.
pub const SEEDS_MAINNET: &[&str] = &[
    "24yjwaf2ni6wz44pmqpw3jyjhksoko7wxzelp6uyep2pdlgb5epbnoqd.onion:8333",
    "2azvsghnhhh6g76vim3s3pmzydlm2yjmncgkucij4wjl276k5djsbtyd.onion:8333",
    "2dusr2lsbpk4hji44en6wf7vxquweavufct7usyrlqk52zuhbva5kbqd.onion:8333",
    "2e55fihc5rjin7ml3h5c2ovoydpatplduo2vfnwgdfy3kykg5irmydad.onion:8333",
    "2fy4h7uj4pz2oxiz3knaazwvcr3vipw27fesmhkewy4qmr5vbzsmw6qd.onion:8333",
    "2fzliqx6qd2d72vub6pg2ajmgf4wfpwbv6lvxeth4gdrwegwd2qp67qd.onion:8333",
    "2gvtabgvanyzjwe45gv7zhyjqc5h7x65hbrg4ra4x43exgeb7u6qg3ad.onion:8333",
    "2hn3bt32nk5grhcvb5d5herx5ens2woakw2inxfprirsfb6uui7rigad.onion:8333",
    "2mgmxraiypx3dwgkzjonwcphkfsmyxyuje6fnbhm4zanfsqwbep5ihyd.onion:8333",
    "2okgq4xsnf5mt5qwblehbe7igp347f2n5wwsiryux6kt4f4ltihkhzqd.onion:8333",
    "2pchc2mx4gc4hc4fi73mcnz3oblaf643fyhhge3u6iwjjfhoukqiarqd.onion:8333",
    "2phc4k7tru2dcldtr6forzquqjrfn27hg4mft4gpiekoro6iqmq4zcid.onion:8333",
    "2rpfeo7y73ozw3lqajale5yhoghlcymmouk7izaxr5tazcy3i6jufeyd.onion:8333",
    "2xwg6nq2yfe7mlgntw7gshohmje2x6mfosoo3gghmncm3rqva76vmaad.onion:8333",
    "2y4axr3g2po2zdl7jwfpndsimu4nplpwc5qnjqiz4allrjsc4vz62zyd.onion:8333",
    "35mh5hu4fosgm64hcak4lnn73bxltli5kigqh4ncvixgt63ubdujlvyd.onion:8333",
    "36hp7stmk5nv6wdvvk6vqhgpdpmpxmjuiklzrihh5u6nhol4nrmu7mqd.onion:8333",
    "3cqhckewjjkecjmublevuun23hjbtgvn5hsmagt5zzfgo3kdr55ezxad.onion:8333",
    "3cuub2bswt2x6sudlvxbc3tafmzetpjluvkjjs5vymw5qhmqsa2galqd.onion:8333",
    "3eieocxbtl6gwvxmskcphaysjhxngvwy2io72q7qas2w3ksy22e65vid.onion:8333",
    "3iya3pzi5st5q32tb2bxh556iuigfgd7scavgkzm6zbxz43nafmyjeqd.onion:8333",
    "3jnpbpcg2fbp5snihnfgdhi2n7t75vj6rub2inxvay2gdeqzyie4l3ad.onion:8333",
    "3kphnfwhbjfwupa2rzgn5kmc2pn46ey2jbgty2ucrp4bcyba552syhyd.onion:8333",
    "3lhkpmm77wq6ttku4ofpeih63qmr4buw3y7ltcfcfcppe6wsascgklyd.onion:8333",
    "3luwe7a3zfffws5pomnhhgqskoxbnnmfwa7xaj75mbddddv2foli7eyd.onion:8333",
    "3n5to4u42crq7mudn4vcnrpfifhvddhxahmyqvbbp576zcr6wpyml6qd.onion:8333",
    "3ny3ejsl5irmnmqxqoy3fnuvhl6d4c2r773lw5hphll5sx5ffmtgviqd.onion:8333",
    "3qnrkstzhtpest65wavnl7emdjm3nsg2iqpiomaq7b6zqtl3sbsvu6qd.onion:8333",
    "3qveg7ehmhnifqrv6sqxakbmu6qfja2bna6c3d5udqzvv76kaxzrjgid.onion:8333",
    "3tur4hvphjmiwcast3wrh6innqhklinmo6ogvycsdldgvc5utvzf42id.onion:8333",
    "3uucsasj5lmadbl2jr7ioubiafhq56bhzifazd6ku6224lnkyrdmmwid.onion:8333",
    "3wl43bwi3muqlnxnhxgl6yo4nrexbkl7m6kvz4ki7mbid5pgsekfmzyd.onion:8333",
    "3ysjehpu3ue7diozsezboulojpiuchnktuwh37gl4b6svvbcx6snn7ad.onion:8333",
    "3zwvcwzcms6qea5jt7x4ye24chkjjaljjkmskbcb3a75qdllzvpngmyd.onion:8333",
    "42pmaeged2fv446gly5pafmjfwp365ihgto4l2gkqxdpwhmf7atxsfid.onion:8333",
    "45pdfgyu2cmn3ohaet55ecerccr3yrizxhvmrypxecbwkbqaxq57twyd.onion:8333",
    "46mz4aoecgf5466fzt3wf5si6c3zfft4i7m76rifkhxqpbftkv6duaad.onion:8333",
    "47do6hlpybnudbsbuy2t2k5wacthnpogv6q5ta7oim5xymyrtylskkid.onion:8333",
    "4ayy4p2lsqe7c3qurbhskda3gauncgsilpz33wgcouzq42npwnxahjqd.onion:8333",
    "4de54h5kxxa7uh3iyq67x5uo7oyq5gvakvzuz3zphr7uuldjhrdmbhad.onion:8333",
    "4gdpbxnml5r7jhudps34tqr5jrc5cuh5ilaugbozbrrq4vg3qz73wmyd.onion:8333",
    "4jnssqcipbs63t67ehr2znjjmgbsm44w2rle5bo5w7aostbwf5kk3hqd.onion:8333",
    "4jy6egjkn6qn7zv2z2i36hsxo4mkbcyfd3xn5gtet4fyfpzw3tt6k2id.onion:8333",
    "4mjozyewnamgx2cqsaafumoewghmeslzglmgy7zmc4knmrzxl5532byd.onion:8333",
    "4mrdv7acqgi4mzlzn4hm6pvgvuwpaglkxekfjocsmqy6i6mlrzdkptad.onion:8333",
    "4p574crtb7fxcyafrx6ittdiik65b4zsk5yi6l7wsmkv2zw7dcofpuyd.onion:8333",
    "4tbxofzwvmkl6aemgjws32twrbuz4kniydrr5sflgeqijkarif5oawid.onion:8333",
    "4tuumpmjia5rkhrgfc6kzuflvkh2r726v2erkg2yfmpezkr2jptczaad.onion:8333",
];
/// Testnet4 onion peers, from Bitcoin Core's `contrib/seeds/nodes_testnet4.txt` (read 2026-10-30).
pub const SEEDS_TESTNET4: &[&str] = &[
    "2sltzrq7ts5t4il5nimp75og2jksbwdjmgbdykz5ljeoqrxemzlakeyd.onion:48333",
    "2z57dvvbbhf6ratvxohwg5rmlohk2d6kke5fxlilglgjfp7gj25hlbad.onion:48333",
    "33ffm6iijgivx7xyg75isr5cd2thsqsx7c5hwab5pu3u774uwuipsdqd.onion:48333",
    "4uzerod2wrqtjuaea6vr43uddq2sg3cgfuk4khqotqsqdsxpwdmcphqd.onion:48333",
    "4xjpowmbirjgmjfsblwkyd2a26b4pnfvplrsopkbtfomelgtgmdbmlad.onion:48333",
    "5f2qaud736uqiqqnjesbfvdkalllrdnkrkyinfx4bl4e7ybxd3h6hsad.onion:48333",
    "5fkz5ijh76cgfwvxz4pyl4br4hekqflijz7d467ldey3xme2trqrgjad.onion:48333",
    "5p6eqvrins6vj7q3tpdljhtomu6nqameilbuz5sjnu2i333ve2zpnhqd.onion:48333",
    "5qmffxnezxp663btesdfvfudkf3pucjla25utnna7mlbtbcp2p4nosqd.onion:48333",
    "5rh3ln6ypycmn57qlmke3dliffg2id3ziz4dhsujng4tk34oklnbqtyd.onion:48333",
    "5sdzs2qu3ygb44jwo45y2kmbnqc6ijzpndaqn43zgngsiwq7mx6b7yyd.onion:48333",
    "5wpcussznj2dg5222zrtfdsx5ttco6xlv7447azzaaywu2t5xukqcaqd.onion:48333",
    "6g6dwtby74ic2ggnzkbfqy7saslopho7or6z4uad737c2tq24fj3ltyd.onion:48333",
    "6po3e27t4nxgls3mwnostpy47crhtc3ae6fcsn4yyfh5dfcaq3q3q3yd.onion:48333",
    "7jd422hqevrz334ax3fh77wzww7clnr4kpyos25oe64nifg623bjqfqd.onion:48333",
    "7kwh7rg3a4e5lgjvybesixzhwzxvf6dqo3gc4h7k5vilwmdjvtzidtid.onion:48333",
    "7z36qr6zyhxe4dvv6inp72qgaheyp27fvsvvtkjeqfhhdgqwbh3wkyid.onion:48333",
    "a3aej552sklp5nhrosr5wv7qylgkmnu5u7zh7se56vtllvhgctzkbjqd.onion:48333",
    "a6yijgwn4vtmmhl7uybtbuyvtl7mtj7arld5f4csqsx4syeii4gt3vqd.onion:48333",
    "aqabn424rm7qq5faw2ecckkzxfdw57oncivjrurrrn5wgjdqjqxvxjad.onion:48333",
    "azccjliswzu5aycse7g7zu2bw3mqicd2mhszczitp332scjgltehrjqd.onion:48333",
    "bv2uuihcluruxlt4zwedditinsjberjtaj7yciwd25nrhy3ufh7jjvqd.onion:48333",
    "c7nbt6bs5c7foimwc4wmwlrqd7fg22r76i22nglv2inx7tsav677gzyd.onion:48333",
    "clqr2to2r6fn4jo6f7xy3dppxgn4ewvnmwbxsdrrhnesyacmw5noaeqd.onion:48333",
    "cz3mmv4xdls7ha45hcb4ibtlgm746awd4x6luvlo4ws6rpvbegehvcyd.onion:48333",
    "dnshzxr6osjf2l5gjsbattjtoefgkzmd3p3fdyatr5ltz243zspsilyd.onion:48333",
    "ebhtfcmjhilcqtuls437pxu65dznqkpt5qv3yeq6zipnqd7ichz5htyd.onion:48333",
    "ekwxajjykxkjaasooo2nnp4gnoedhwksg4kykny3ierwfabrwwyweaid.onion:48333",
    "ezbq3ydfxmgvgbbn7mrx5jzyig6tz2zjkaqdtkx7avnijrt5riv4j5yd.onion:48333",
    "f2tt2hdbqlbslvdlpworasoijtqfxlkkcabl2kbu7gptojc2synwq6qd.onion:48333",
    "fsijrllgzgeg4pa5ebq4qy3swmplxkzvuvji5swt36quy42dznq3t3ad.onion:48333",
    "fvbppnodd4dlxulzlvhikg2ijtnxemcjjpfhcg2rropun45aqhp5noid.onion:48333",
    "fwsrcrhnggi3qy5rsfiad3cwep3bf7uovcupgockbntjcfvoqxzr75id.onion:48333",
    "gc66muikqqzxwj2tdvvap6gpcbitthjvscawgkclim4vgmajrccjtmqd.onion:48333",
    "gsw6sn27quwf6u3swgra6o7lrp5qau6kt3ymuyoxgkth6wntzm2bjwyd.onion:48333",
    "gujxforhwszry5falvnarfcyajjxxsuvqevx6gk6meou5ordrxw3mdad.onion:48333",
    "h57ub4bqjrc2kdyppyddf5io2wldegfiycceh7olwf45rjkfsfjceiid.onion:48333",
    "havkohvjhg5tglbdecf4ufhz5es3f33ctj3b6loebj4pi6qrtjemfbyd.onion:48333",
    "hb44egze5hjbi3n2rc6w4pwahr6zltc4ilfzin3kkdi2rmozvxlo65qd.onion:48333",
    "hnguqpsswg2pktx53skxezcj7k27772f5qu7zx62nhurup6cdvlc5dqd.onion:48333",
    "i22efh4itlcfthvaavcz2rvigu4x6jqvlwuksz44bukslhg76bsgrxqd.onion:48333",
    "irwyrdkcrcdgwtsltcrqexqylwc3ezjhhra7u4i3gkwktezcut36buqd.onion:48333",
    "jspxdo33gyrh3tewi55mn2fo5spczzgipq6ao7fa5qu6fj2ezr7bizid.onion:48333",
    "kf6q2wza2ebo7cxln5ejcjjwvrew4vb2hf4vd5wo4nyzbnjv3yccduqd.onion:48333",
    "ko55e2ityiaqeckthmnnbcv6bbwll7rtdiv527muoqdpg4hye2it2pyd.onion:48333",
    "kolvizpy2tctu7tyq5qlquodwcsljtfbmowcxqsihfrlvwlihpsijwad.onion:48333",
    "livxdbwpl4o2tiw3w73qoloqnqnfetpu3h374ez4rik3uyx4ygzzhcid.onion:48333",
    "mavvwxts5f3axuz4cyjqpz75veijkdkdueavekb5hia67zk257eg7tqd.onion:48333",
];

/// One coin at a watched address, with the block that holds it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchedCoin {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value_sats: u64,
    pub height: u32,
    pub block: [u8; 32],
}

/// The watcher's state: the header follower, the agreed filter tip, and the open swaps' scripts and coins.
pub struct Watch {
    pub follower: HeaderFollower,
    /// The last height whose filter was checked: `(height, block hash, agreed filter header)`.
    pub filtered: Option<(u32, [u8; 32], [u8; 32])>,
    /// O1-FOOTPRINT-REVIEWED: one entry per OPEN swap address (dropped by `unwatch` when the swap settles).
    scripts: BTreeMap<Vec<u8>, String>,
    /// O1-FOOTPRINT-REVIEWED: the coins at the open swaps' addresses.
    coins: BTreeMap<String, Vec<WatchedCoin>>,
    /// O1-FOOTPRINT-REVIEWED: the sender scripts of the open swaps' funding transactions.
    funding: BTreeMap<[u8; 32], Vec<Vec<u8>>>,
    /// O1-FOOTPRINT-REVIEWED: per open swap address, the transactions that paid it or spent its coins (a payout's depth is
    /// read here), each with its block — dropped with the address.
    txs: BTreeMap<String, BTreeMap<[u8; 32], (u32, [u8; 32])>>,
}

/// Bitcoin's merkle root over txids (internal order): pairwise `dSHA256`, the last of an odd level paired with itself.
#[must_use]
pub fn merkle_root(txids: &[[u8; 32]]) -> [u8; 32] {
    if txids.is_empty() {
        return [0u8; 32];
    }
    let mut level: Vec<[u8; 32]> = txids.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            let last = level[level.len() - 1];
            level.push(last);
        }
        level = level
            .chunks_exact(2)
            .map(|p| {
                let mut b = [0u8; 64];
                b[..32].copy_from_slice(&p[0]);
                b[32..].copy_from_slice(&p[1]);
                crate::btc_filter::sha256d(&b)
            })
            .collect();
    }
    level[0]
}

fn hash160(b: &[u8]) -> [u8; 20] {
    use bitcoin_hashes::{hash160, Hash};
    hash160::Hash::hash(b).to_byte_array() // CLASSICAL-CRYPTO-EXEMPT: Bitcoin's own script hash, foreign-chain data only
}

/// The script a spent output must have had, recovered from the input that spends it: P2WPKH, P2SH-wrapped P2WPKH or P2WSH,
/// P2WSH and P2PKH reveal it; a taproot spend (its output key never appears) and anything unrecognised do not.
#[must_use]
pub fn spent_script(i: &p2p::TxIn) -> Option<Vec<u8>> {
    use sha2::{Digest, Sha256};
    let w = &i.witness;
    let control_block = |b: &[u8]| !b.is_empty() && (b[0] & 0xfe) == 0xc0 && b.len() >= 33 && (b.len() - 33) % 32 == 0;
    if !w.is_empty() {
        if w.len() == 1 || w.last().is_some_and(|b| control_block(b)) {
            return None; // taproot: key path (one signature) or script path (a control block) — the output key is not here
        }
        let pk_spend = w.len() == 2 && w[1].len() == 33 && matches!(w[1][0], 2 | 3);
        let program: Vec<u8> = if pk_spend {
            [&[0x00, 0x14][..], &hash160(&w[1])[..]].concat()
        } else {
            let ws = w.last()?;
            [&[0x00, 0x20][..], &Sha256::digest(ws)[..]].concat()
        };
        if i.script_sig.is_empty() {
            return Some(program); // native segwit
        }
        // P2SH-wrapped: the scriptSig pushes exactly the witness program
        let pushed = i.script_sig.get(1..)?;
        if usize::from(i.script_sig[0]) != pushed.len() || pushed != program.as_slice() {
            return None;
        }
        return Some([&[0xa9, 0x14][..], &hash160(pushed)[..], &[0x87][..]].concat());
    }
    // P2PKH: <sig> <33- or 65-byte pubkey>
    let s = &i.script_sig;
    let sig_len = usize::from(*s.first()?);
    let rest = s.get(1 + sig_len..)?;
    let pk_len = usize::from(*rest.first()?);
    let pk = rest.get(1..)?;
    if pk.len() != pk_len || !(pk_len == 33 || pk_len == 65) {
        return None;
    }
    Some([&[0x76, 0xa9, 0x14][..], &hash160(pk)[..], &[0x88, 0xac][..]].concat())
}

impl Watch {
    #[must_use]
    pub fn new(params: Params, cp: Checkpoint) -> Self {
        Watch {
            follower: HeaderFollower::new(params, cp),
            filtered: None,
            scripts: BTreeMap::new(),
            coins: BTreeMap::new(),
            funding: BTreeMap::new(),
            txs: BTreeMap::new(),
        }
    }

    /// Watch `address` (its scriptPubKey). A NEW script re-checks the follower's one-day ring of filters, so a deposit
    /// already in a block when the address was registered is still found.
    pub fn watch(&mut self, address: &str, script: Vec<u8>) {
        if self.scripts.insert(script, address.to_string()).is_none() {
            self.filtered = None;
        }
    }

    /// A settled swap's address: its script, coins and senders leave.
    pub fn unwatch(&mut self, address: &str) {
        self.scripts.retain(|_, a| a != address);
        if let Some(cs) = self.coins.remove(address) {
            for c in cs {
                self.funding.remove(&c.txid);
            }
        }
        self.txs.remove(address);
    }

    /// The addresses watched now.
    #[must_use]
    pub fn addresses(&self) -> Vec<String> {
        let mut v: Vec<String> = self.scripts.values().cloned().collect();
        v.sort();
        v.dedup();
        v
    }

    /// The watched scripts (what a filter is matched against).
    #[must_use]
    pub fn scripts(&self) -> Vec<&[u8]> {
        self.scripts.keys().map(Vec::as_slice).collect()
    }

    /// ⭐ Apply one block whose filter matched: its transactions count only if their merkle root is the one in `header` — a
    /// header the follower took by proof of work. Outputs to a watched script become coins; inputs spending a watched coin
    /// remove it; each new coin's funding transaction yields its senders where the inputs reveal them.
    pub fn apply_block(&mut self, height: u32, header: &[u8; 80], txs: &[Tx]) -> Result<(), &'static str> {
        let txids: Vec<[u8; 32]> = txs.iter().map(|t| t.txid).collect();
        if merkle_root(&txids)[..] != header[36..68] {
            return Err("the block's transactions are not the ones its header commits to");
        }
        let block = header_hash(header);
        for t in txs {
            for i in &t.inputs {
                for (addr, cs) in self.coins.iter_mut() {
                    let before = cs.len();
                    cs.retain(|c| !(c.txid == i.prev_txid && c.vout == i.prev_vout));
                    if cs.len() != before {
                        self.txs.entry(addr.clone()).or_default().insert(t.txid, (height, block)); // a payout from it
                    }
                }
            }
            for (vout, o) in t.outputs.iter().enumerate() {
                let Some(addr) = self.scripts.get(&o.script).cloned() else { continue };
                let coin = WatchedCoin { txid: t.txid, vout: vout as u32, value_sats: o.value, height, block };
                self.txs.entry(addr.clone()).or_default().insert(t.txid, (height, block));
                let list = self.coins.entry(addr).or_default();
                if !list.iter().any(|c| c.txid == coin.txid && c.vout == coin.vout) {
                    list.push(coin);
                }
                if let Some(senders) = t.inputs.iter().map(spent_script).collect::<Option<Vec<_>>>() {
                    self.funding.insert(t.txid, senders);
                }
            }
        }
        Ok(())
    }

    /// Confirmations of a coin on the most-work chain: from the follower's ring when its block is there; `0` when its block
    /// was replaced by a reorg (the coin is then dropped by [`Self::prune_reorged`]); counted from its height when older than
    /// the ring (a day deep).
    #[must_use]
    pub fn confirmations(&self, c: &WatchedCoin) -> u64 {
        if let Some(n) = self.follower.confirmations(&c.block) {
            return u64::from(n);
        }
        let tip = self.follower.tip().height;
        let oldest = tip.saturating_sub(crate::btc_filter::RING as u32 - 1);
        if c.height < oldest {
            u64::from(tip - c.height + 1)
        } else {
            0
        }
    }

    /// Coins whose block left the most-work chain are forgotten, and the filter tip steps back to re-check from there.
    pub fn prune_reorged(&mut self) {
        let tip = self.follower.tip().height;
        let oldest = tip.saturating_sub(crate::btc_filter::RING as u32 - 1);
        let mut lowest_lost: Option<u32> = None;
        for cs in self.coins.values_mut() {
            cs.retain(|c| {
                let keep = c.height < oldest || self.follower.confirmations(&c.block).is_some();
                if !keep {
                    lowest_lost = Some(lowest_lost.map_or(c.height, |l| l.min(c.height)));
                }
                keep
            });
        }
        if let Some((h, hash, _)) = self.filtered {
            if h >= oldest && self.follower.confirmations(&hash).is_none() {
                self.filtered = None; // the checked tip itself was replaced: re-agree from the ring
            }
        }
        if lowest_lost.is_some() {
            self.filtered = None;
        }
    }

    /// The coins at `address` with their confirmations, in the deposit watcher's shape.
    #[must_use]
    pub fn reserve_coins(&self, address: &str) -> Vec<crate::btc_watch::ReserveCoin> {
        self.coins.get(address).map_or_else(Vec::new, |cs| {
            cs.iter()
                .map(|c| crate::btc_watch::ReserveCoin { txid: c.txid, vout: c.vout, value_sats: c.value_sats, confirmations: self.confirmations(c) })
                .collect()
        })
    }

    /// A watched coin's value and script (the payout builder's read): `None` for a coin this watcher does not hold.
    #[must_use]
    pub fn tx_out(&self, txid: &[u8; 32], vout: u32) -> Option<(u64, Vec<u8>)> {
        self.coins.iter().find_map(|(addr, cs)| {
            let c = cs.iter().find(|c| c.txid == *txid && c.vout == vout)?;
            let script = self.scripts.iter().find(|(_, a)| *a == addr).map(|(s, _)| s.clone())?;
            Some((c.value_sats, script))
        })
    }

    /// How deep a transaction that paid or spent a watched address is on the most-work chain (`None`: not seen here).
    #[must_use]
    pub fn tx_confirmations(&self, txid: &[u8; 32]) -> Option<u64> {
        let (height, block) = self.txs.values().find_map(|m| m.get(txid)).copied()?;
        Some(self.confirmations(&WatchedCoin { txid: *txid, vout: 0, value_sats: 0, height, block }))
    }

    /// The funding transaction's senders, where its inputs revealed them.
    #[must_use]
    pub fn funding_scripts(&self, txid: &[u8; 32]) -> Option<Vec<Vec<u8>>> {
        self.funding.get(txid).cloned()
    }
}

/// One filter peer: an onion service speaking Bitcoin's protocol that serves compact filters and witness blocks.
pub struct Peer {
    pub onion: String,
    stream: std::net::TcpStream,
    magic: [u8; 4],
}

impl Peer {
    /// Connect through `proxy` and handshake; refused unless the peer serves compact filters AND witness blocks.
    pub fn connect(proxy: &str, onion: &str, port: u16, magic: [u8; 4], timeout: std::time::Duration) -> Result<Self, String> {
        let stream = p2p::socks5_connect(proxy, onion, port, timeout).map_err(|e| e.to_string())?;
        let mut p = Peer { onion: onion.to_string(), stream, magic };
        let nonce = u64::from_le_bytes(blake3::hash(onion.as_bytes()).as_bytes()[..8].try_into().map_err(|_| "nonce")?);
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs() as i64;
        p.send("version", &p2p::version_payload(nonce, 0, now))?;
        let mut services = None;
        let mut verack = false;
        for _ in 0..16 {
            let (cmd, payload) = p.recv()?;
            match cmd.as_str() {
                "version" => {
                    let (_, s, _) = p2p::parse_version(&payload).ok_or("an unreadable version")?;
                    services = Some(s);
                    p.send("verack", &[])?;
                }
                "verack" => verack = true,
                _ => {}
            }
            if verack && services.is_some() {
                break;
            }
        }
        let s = services.ok_or("no version")?;
        if !verack || s & p2p::NODE_COMPACT_FILTERS == 0 || s & p2p::NODE_WITNESS == 0 {
            return Err("the peer serves no compact filters or no witness blocks".into());
        }
        Ok(p)
    }

    fn send(&mut self, cmd: &str, payload: &[u8]) -> Result<(), String> {
        use std::io::Write;
        self.stream.write_all(&p2p::frame(self.magic, cmd, payload)).map_err(|e| e.to_string())
    }

    /// The next message, answering a `ping` on the way; a bad checksum or another network's frame ends the session.
    fn recv(&mut self) -> Result<(String, Vec<u8>), String> {
        use std::io::Read;
        loop {
            let mut h = [0u8; 24];
            self.stream.read_exact(&mut h).map_err(|e| e.to_string())?;
            let (cmd, len, sum) = p2p::read_header(self.magic, &h).ok_or("a frame of another network or over the bound")?;
            let mut payload = vec![0u8; len];
            self.stream.read_exact(&mut payload).map_err(|e| e.to_string())?;
            if !p2p::checksum_ok(&payload, sum) {
                return Err("a frame failed its checksum".into());
            }
            if cmd == "ping" {
                self.send("pong", &payload)?;
                continue;
            }
            return Ok((cmd, payload));
        }
    }

    /// Ask, then wait for the answer `want` (other messages are skipped), at most `limit` messages.
    fn ask(&mut self, cmd: &str, payload: &[u8], want: &str, limit: usize) -> Result<Vec<u8>, String> {
        self.send(cmd, payload)?;
        for _ in 0..limit {
            let (c, p) = self.recv()?;
            if c == want {
                return Ok(p);
            }
        }
        Err(format!("no {want} within {limit} messages"))
    }
}

/// The most headers one sweep feeds the follower before checking their filters (kept within the follower's one-day ring, so
/// every height checked still has its hash).
pub const FILTER_BATCH: usize = 100;

/// ⭐ ONE SWEEP: follow headers from the peers, then check every new block's filter under the three-peer agreement, fetch
/// the blocks that match and apply them. Returns how many blocks' filters were checked. A peer that breaks a rule is dropped.
pub fn sweep(watch: &mut Watch, peers: &mut Vec<Peer>) -> Result<usize, String> {
    if peers.len() < crate::btc_filter::MIN_FILTER_PEERS {
        return Ok(0); // fewer than three filter peers: nothing counts yet (fail closed — no deposit is confirmed)
    }
    // 1. headers, by Bitcoin's rules, from the first peer that answers
    let locator = vec![watch.follower.tip().hash];
    let headers = peers[0].ask("getheaders", &p2p::getheaders_payload(&locator, &[0u8; 32]), "headers", 64)?;
    let headers = p2p::parse_headers(&headers).ok_or("an unreadable headers message")?;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|e| e.to_string())?.as_secs();
    let mut checked = 0usize;
    for chunk in headers.chunks(FILTER_BATCH) {
        watch.follower.accept(chunk, now).map_err(|r| format!("a header broke Bitcoin's rules: {r:?}"))?;
        watch.prune_reorged();
        checked += check_filters(watch, peers)?;
    }
    if headers.is_empty() {
        checked += check_filters(watch, peers)?;
    }
    Ok(checked)
}

/// Check the filters from the agreed filter tip up to the follower's tip (within its ring).
fn check_filters(watch: &mut Watch, peers: &mut [Peer]) -> Result<usize, String> {
    let tip = watch.follower.tip();
    let start = match watch.filtered {
        Some((h, _, _)) => h + 1,
        None => watch.follower.oldest().height,
    };
    if start > tip.height {
        return Ok(0);
    }
    let stop = tip.hash;
    // the filter headers, from every peer; the stop header must be agreed by three and the chain must start at our tip
    let mut answers = Vec::new();
    let mut chains = Vec::new();
    for p in peers.iter_mut() {
        if let Ok(m) = p.ask("getcfheaders", &p2p::filter_request_payload(start, &stop), "cfheaders", 64) {
            if let Some((s, prev, hashes)) = p2p::parse_cfheaders(&m) {
                let continues = watch.filtered.map_or(true, |(_, _, fh)| fh == prev);
                if s == stop && continues && hashes.len() == (tip.height - start + 1) as usize {
                    let hs = p2p::chain_filter_headers(&prev, &hashes);
                    if let Some(last) = hs.last() {
                        answers.push((*blake3::hash(p.onion.as_bytes()).as_bytes(), *last));
                        chains.push((hashes, hs));
                    }
                }
            }
        }
    }
    let agreed = match agree(&answers) {
        Agreement::Agreed(h) => h,
        Agreement::Wait | Agreement::Conflict => return Ok(0), // nothing counts by majority: ask again next sweep
    };
    let Some((hashes, hs)) = chains.into_iter().find(|(_, hs)| hs.last() == Some(&agreed)) else { return Ok(0) };
    // the filters themselves, from one peer, each held to its agreed hash
    let m_peer = &mut peers[0];
    m_peer.send("getcfilters", &p2p::filter_request_payload(start, &stop))?;
    let scripts: Vec<Vec<u8>> = watch.scripts().into_iter().map(<[u8]>::to_vec).collect();
    let mut wanted = Vec::new();
    for k in 0..hashes.len() {
        let height = start + k as u32;
        let (cmd, payload) = loop {
            let (c, p) = m_peer.recv()?;
            if c == "cfilter" {
                break (c, p);
            }
        };
        let _ = cmd;
        let (block, filter) = p2p::parse_cfilter(&payload).ok_or("an unreadable cfilter")?;
        if crate::btc_filter::sha256d(&filter) != hashes[k] {
            return Err("a filter is not the one its agreed header commits to".into());
        }
        let refs: Vec<&[u8]> = scripts.iter().map(Vec::as_slice).collect();
        if crate::btc_filter::matches_any(&block, &filter, &refs) == Some(true) {
            wanted.push((height, block));
        }
    }
    for (height, block) in wanted {
        let raw = m_peer.ask("getdata", &p2p::getdata_block_payload(&block), "block", 64)?;
        let (header, txs) = p2p::parse_block(&raw).ok_or("an unreadable block")?;
        if header_hash(&header) != block || watch.follower.confirmations(&block).is_none() {
            return Err("a block that is not the followed chain's".into());
        }
        watch.apply_block(height, &header, &txs)?;
    }
    watch.filtered = Some((tip.height, tip.hash, agreed));
    let _ = hs;
    Ok(hashes.len())
}

/// How many filter peers a watcher keeps (≥ `MIN_FILTER_PEERS`, so one leaving never stops the agreement).
pub const PEERS_KEPT: usize = 6;
/// The pause between sweeps (a block is ten minutes; a deposit is seen within one sweep of its block).
pub const SWEEP_PAUSE: std::time::Duration = std::time::Duration::from_secs(30);
/// One onion connect or reply may take this long before the peer is set aside.
pub const PEER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// What one network's watcher publishes after each sweep — readers take this snapshot and never wait on the network.
struct Shared {
    watch: Watch,
    /// Addresses to watch, as the deposit watcher registers and retires them (applied at the next sweep).
    want: BTreeMap<String, Vec<u8>>,
    /// Raw transactions to hand the peers at the next sweep (a payout's broadcast).
    outbox: Vec<Vec<u8>>,
}

fn shared(net: crate::btc_tx::BtcNet) -> Option<&'static std::sync::Mutex<Shared>> {
    use crate::btc_tx::BtcNet;
    static MAIN: std::sync::OnceLock<std::sync::Mutex<Shared>> = std::sync::OnceLock::new();
    static TEST4: std::sync::OnceLock<std::sync::Mutex<Shared>> = std::sync::OnceLock::new();
    let (cell, params, cp) = match net {
        BtcNet::Mainnet => (&MAIN, crate::btc_filter::MAINNET, CHECKPOINT_MAINNET),
        BtcNet::Testnet => (&TEST4, crate::btc_filter::TESTNET4, CHECKPOINT_TESTNET4),
        _ => return None, // regtest is reached through its own Bitcoin Core only
    };
    Some(cell.get_or_init(|| std::sync::Mutex::new(Shared { watch: Watch::new(params, cp), want: BTreeMap::new(), outbox: Vec::new() })))
}

fn lock(m: &std::sync::Mutex<Shared>) -> std::sync::MutexGuard<'_, Shared> {
    // a poisoned lock holds the last snapshot a sweep published: it is read as it stands
    match m.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// Register `address` for watching on its network (its script from `btc_tx`); `false` for an address no watcher serves.
pub fn watch_address(address: &str) -> bool {
    let Some((net, script)) = crate::btc_tx::script_pubkey_for_address(address) else { return false };
    let Some(m) = shared(net) else { return false };
    lock(m).want.insert(address.to_string(), script);
    true
}

/// A settled swap's address leaves the watcher.
pub fn retire_address(address: &str) {
    let Some((net, _)) = crate::btc_tx::script_pubkey_for_address(address) else { return };
    if let Some(m) = shared(net) {
        let mut g = lock(m);
        g.want.remove(address);
        g.watch.unwatch(address);
    }
}

/// Read the published snapshot of `net`'s watcher.
pub fn with_watch<R>(net: crate::btc_tx::BtcNet, f: impl FnOnce(&Watch) -> R) -> Option<R> {
    shared(net).map(|m| f(&lock(m).watch))
}

/// Hand a signed transaction to `net`'s filter peers at the next sweep; its txid (display hex), from its own bytes.
pub fn broadcast(net: crate::btc_tx::BtcNet, raw: &[u8]) -> Option<String> {
    let mut r = p2p::Reader::new(raw);
    let txid = p2p::parse_tx(&mut r)?.txid;
    lock(shared(net)?).outbox.push(raw.to_vec());
    Some(crate::btc_tx::txid_display_hex(&txid))
}

/// ⭐ Start `net`'s watcher once: a thread that keeps up to [`PEERS_KEPT`] filter peers among the release's onion seeds
/// (through the node's Tor SOCKS — none, no watcher: never a direct path), applies the registered addresses, hands any
/// pending broadcast to every peer, sweeps, and publishes the result.
pub fn start(net: crate::btc_tx::BtcNet) {
    use crate::btc_tx::BtcNet;
    static STARTED_MAIN: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    static STARTED_TEST4: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    let (once, seeds, magic) = match net {
        BtcNet::Mainnet => (&STARTED_MAIN, SEEDS_MAINNET, p2p::MAGIC_MAINNET),
        BtcNet::Testnet => (&STARTED_TEST4, SEEDS_TESTNET4, p2p::MAGIC_TESTNET4),
        _ => return,
    };
    let Some(m) = shared(net) else { return };
    if once.set(()).is_err() {
        return;
    }
    std::thread::spawn(move || {
        let mut peers: Vec<Peer> = Vec::new();
        let mut next_seed = 0usize;
        loop {
            if let Ok(proxy) = std::env::var("MONEROUSD_TOR_SOCKS") {
                let mut tries = 0;
                while peers.len() < PEERS_KEPT && tries < seeds.len() {
                    let seed = seeds[next_seed % seeds.len()];
                    next_seed += 1;
                    tries += 1;
                    let Some((host, port)) = seed.rsplit_once(':').and_then(|(h, p)| p.parse::<u16>().ok().map(|p| (h, p))) else {
                        continue; // every shipped seed is host:port (pinned by `checkpoint_headers_verify`)
                    };
                    if peers.iter().any(|p| p.onion == host) {
                        continue;
                    }
                    if let Ok(p) = Peer::connect(&proxy, host, port, magic, PEER_TIMEOUT) {
                        peers.push(p);
                    }
                }
            }
            // the registered addresses, then a working copy the network round runs on (readers keep the last snapshot)
            let (mut work, outbox) = {
                let mut g = lock(m);
                let want = g.want.clone();
                for a in g.watch.addresses() {
                    if !want.contains_key(&a) {
                        g.watch.unwatch(&a);
                    }
                }
                for (a, script) in want {
                    g.watch.watch(&a, script);
                }
                (g.watch.clone_state(), std::mem::take(&mut g.outbox))
            };
            for raw in &outbox {
                peers.retain_mut(|p| p.send("tx", raw).is_ok());
            }
            match sweep(&mut work, &mut peers) {
                Ok(_) => lock(m).watch = work,
                Err(why) => {
                    // the peer that broke a rule or went away is set aside; another takes its place next round
                    eprintln!("[btc-watch] a filter peer was set aside: {why}");
                    if !peers.is_empty() {
                        peers.remove(0);
                    }
                }
            }
            std::thread::sleep(SWEEP_PAUSE);
        }
    });
}

impl Watch {
    /// A copy for one network round (the snapshot readers see is replaced only when the round completes).
    #[must_use]
    pub fn clone_state(&self) -> Watch {
        Watch {
            follower: self.follower.clone(),
            filtered: self.filtered,
            scripts: self.scripts.clone(),
            coins: self.coins.clone(),
            funding: self.funding.clone(),
            txs: self.txs.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
    }

    /// ⭐ §22 6 — THE RELEASE CHECKPOINTS ARE BITCOIN'S OWN HEADERS: for mainnet and testnet4, every shipped header hashes to the
    /// hash it is listed under, the eleven link parent to child, each meets its own target, and the checkpoint's fields are
    /// exactly those headers' (its hash, bits, period start time and difficulty, the eleven timestamps) — the explorer they
    /// were read from is trusted for nothing.
    #[test]
    fn checkpoint_headers_verify() {
        for (cp, headers) in [(CHECKPOINT_MAINNET, CHECKPOINT_MAINNET_HEADERS), (CHECKPOINT_TESTNET4, CHECKPOINT_TESTNET4_HEADERS)] {
            let parsed: Vec<(u32, [u8; 80])> = headers.iter().map(|(h, hash, hex)| {
                let b: [u8; 80] = unhex(hex).try_into().expect("80 bytes");
                assert_eq!(header_hash(&b), hex32(hash), "height {h}: the header is the one named");
                assert!(crate::btc_filter::header_pow_ok(&b), "height {h}: proof of work");
                (*h, b)
            }).collect();
            for w in parsed[1..].windows(2) {
                assert_eq!(w[1].1[4..36], header_hash(&w[0].1)[..], "height {}: links to its parent", w[1].0);
            }
            let (period, last) = (parsed[0].1, parsed[parsed.len() - 1]);
            assert_eq!((cp.height, cp.hash), (last.0, header_hash(&last.1)));
            assert_eq!(cp.bits, crate::btc_filter::header_bits(&last.1));
            assert_eq!(cp.period_first_time, u32::from_le_bytes(period[68..72].try_into().expect("4")));
            assert_eq!(cp.period_bits, crate::btc_filter::header_bits(&period));
            assert_eq!(parsed[0].0 % 2016, 0, "the period's first block");
            let times: Vec<u32> = parsed[1..].iter().map(|(_, b)| u32::from_le_bytes(b[68..72].try_into().expect("4"))).collect();
            assert_eq!(cp.times.to_vec(), times);
        }
        assert!(SEEDS_MAINNET.iter().chain(SEEDS_TESTNET4).all(|s| s.split(':').next().is_some_and(|h| h.ends_with(".onion") && h.len() == 62)), "onion v3 only");
    }

    /// The merkle root of a vector block's parsed transactions is the one in its header (Bitcoin's own odd-level rule
    /// included), and a reordered or dropped transaction breaks it.
    /// TWO-PARTY-REVIEWED: the second party is Bitcoin Core — its own blocks from its test data.
    #[test]
    fn the_merkle_root_of_parsed_transactions_is_the_headers() {
        for (height, _, block, _, _) in crate::btc_p2p::tests_blocks() {
            let (header, txs) = crate::btc_p2p::parse_block(&unhex(block)).expect("parses");
            let ids: Vec<[u8; 32]> = txs.iter().map(|t| t.txid).collect();
            assert_eq!(merkle_root(&ids)[..], header[36..68], "height {height}");
            if ids.len() > 1 {
                let mut swapped = ids.clone();
                swapped.swap(0, 1);
                assert_ne!(merkle_root(&swapped)[..], header[36..68], "height {height}: order matters");
                assert_ne!(merkle_root(&ids[..ids.len() - 1])[..], header[36..68], "height {height}: a dropped tx");
            }
        }
    }

    /// ⭐⭐⭐ §22 6 — A DEPOSIT IS SEEN ONLY IN A BLOCK ITS HEADER COMMITS TO, COUNTED BY THE FOLLOWED CHAIN, AND SPENT AWAY: the
    /// watched script's output in a vector block becomes a coin (its value and txid), a block whose transactions are not the
    /// ones its header commits to is refused and adds nothing, and a spend of the coin removes it; an unwatched address
    /// sees nothing.
    /// TWO-PARTY-REVIEWED: Bitcoin Core's own block bytes are the other party.
    #[test]
    fn a_watched_output_becomes_a_coin_only_from_a_committed_block_and_a_spend_removes_it() {
        let (height, _, block, _, _) = crate::btc_p2p::tests_blocks()[4];
        let (header, txs) = crate::btc_p2p::parse_block(&unhex(block)).expect("parses");
        let (t, vout) = txs.iter().find_map(|t| t.outputs.iter().position(|o| !o.script.is_empty()).map(|v| (t, v))).expect("an output");
        let script = t.outputs[vout].script.clone();
        let value = t.outputs[vout].value;
        let cp = CHECKPOINT_MAINNET;
        let mut w = Watch::new(crate::btc_filter::MAINNET, cp);
        w.watch("bc1-watched", script);
        let mut forged = txs.clone();
        forged.pop();
        assert!(w.apply_block(height, &header, &forged).is_err(), "⛔ a block missing a transaction was applied");
        assert!(w.reserve_coins("bc1-watched").is_empty(), "⛔ a refused block added a coin");
        w.apply_block(height, &header, &txs).expect("the committed block applies");
        let coins = w.reserve_coins("bc1-watched");
        assert!(coins.iter().any(|c| c.txid == t.txid && c.vout == vout as u32 && c.value_sats == value), "the deposit is a coin");
        assert!(w.reserve_coins("bc1-other").is_empty(), "an unwatched address sees nothing");
        // a later block spending the coin removes it (the spend is its own committed block)
        let spend = Tx {
            txid: [9; 32],
            inputs: vec![p2p::TxIn { prev_txid: t.txid, prev_vout: vout as u32, script_sig: vec![], witness: vec![vec![1; 64]] }],
            outputs: vec![],
        };
        let mut h2 = header;
        h2[36..68].copy_from_slice(&merkle_root(&[spend.txid]));
        w.apply_block(height + 1, &h2, &[spend]).expect("a committed spend");
        assert!(!w.reserve_coins("bc1-watched").iter().any(|c| c.txid == t.txid && c.vout == vout as u32), "the spend removed it");
        w.unwatch("bc1-watched");
        assert!(w.scripts().is_empty(), "a settled swap's script leaves");
    }

    /// The sender a spend reveals: P2WPKH and its P2SH wrapping, P2WSH and P2PKH give their scripts; a taproot key-path or
    /// script-path spend gives none (its output key is not on the spend).
    #[test]
    fn a_spend_reveals_its_senders_script_except_taproot() {
        let pk = { let mut v = vec![2u8]; v.extend_from_slice(&[7u8; 32]); v };
        let h = hash160(&pk);
        let wpkh = p2p::TxIn { prev_txid: [0; 32], prev_vout: 0, script_sig: vec![], witness: vec![vec![1; 71], pk.clone()] };
        assert_eq!(spent_script(&wpkh), Some([&[0x00, 0x14][..], &h[..]].concat()));
        let prog = [&[0x00, 0x14][..], &h[..]].concat();
        let mut sig = vec![prog.len() as u8];
        sig.extend_from_slice(&prog);
        let wrapped = p2p::TxIn { script_sig: sig, ..wpkh.clone() };
        assert_eq!(spent_script(&wrapped), Some([&[0xa9, 0x14][..], &hash160(&prog)[..], &[0x87][..]].concat()));
        let mut p2pkh_sig = vec![71u8];
        p2pkh_sig.extend_from_slice(&[1u8; 71]);
        p2pkh_sig.push(33);
        p2pkh_sig.extend_from_slice(&pk);
        let p2pkh = p2p::TxIn { prev_txid: [0; 32], prev_vout: 0, script_sig: p2pkh_sig, witness: vec![] };
        assert_eq!(spent_script(&p2pkh), Some([&[0x76, 0xa9, 0x14][..], &h[..], &[0x88, 0xac][..]].concat()));
        let key_path = p2p::TxIn { prev_txid: [0; 32], prev_vout: 0, script_sig: vec![], witness: vec![vec![3; 64]] };
        assert_eq!(spent_script(&key_path), None, "a taproot key-path spend hides its output key");
        let mut cb = vec![0xc0];
        cb.extend_from_slice(&[5; 32]);
        let script_path = p2p::TxIn { witness: vec![vec![3; 64], vec![0x51], cb], ..key_path };
        assert_eq!(spent_script(&script_path), None, "a taproot script-path spend hides its output key");
    }
}
