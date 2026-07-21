// Hand-curated search synonyms for terms the Unicode emoji names miss — 🔫 is
// "pistol" not "gun", 😂 is "tears of joy" not "lol". ORed into the picker
// search alongside the generated EMOJI_NAMES. Kept separate from the generated
// data so regenerating emoji_data.ts never clobbers it.

export const EMOJI_KEYWORDS: Record<string, string> = {
  "🔫": "gun weapon pistol shoot",
  "💣": "bomb explosive",
  "🔪": "knife weapon stab",
  "🗡️": "sword dagger blade weapon",
  "⚔️": "swords weapon fight battle",
  "🪓": "axe weapon chop",
  "🧨": "dynamite explosive",
  "😂": "lol laugh laughing funny haha",
  "🤣": "lol laugh rofl laughing funny",
  "😭": "cry crying sob sad",
  "😢": "cry crying sad tear",
  "❤️": "love heart",
  "👍": "thumbsup yes good like approve",
  "👎": "thumbsdown no bad dislike",
  "🔥": "fire lit hot flame",
  "💀": "skull dead death rip",
  "🎉": "party celebrate confetti yay",
  "😍": "love heart eyes crush",
  "🥺": "pleading puppy eyes please beg",
  "😎": "cool sunglasses",
  "🤔": "thinking hmm think",
  "🙏": "pray please thanks thank you high five",
  "💩": "poop poo crap",
  "🤮": "puke vomit sick barf",
  "🥳": "party celebrate birthday",
  "😴": "sleep sleeping tired zzz",
  "🤯": "mind blown shocked",
  "😡": "angry mad rage",
  "🥶": "cold freezing",
  "🥵": "hot heat",
  "👀": "eyes look watching sus",
};
