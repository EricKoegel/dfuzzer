/** @file unsafe-strings.h */
/*
 * dfuzzer - tool for fuzz testing processes communicating through D-Bus.
 *
 * Copyright(C) 2013, Red Hat, Inc., Matus Marhefka <mmarhefk@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef UNSAFE_STRINGS_H
#define UNSAFE_STRINGS_H

/**
	Array of strings, which will be send to tested process if it has any string
	parameters. Feel free to include any strings here (only valid UTF-8).
	Array must be terminated by NULL string.
*/
/**
    Most of these are taken from the Big List of Naughty Strings repo
    https://github.com/minimaxir/big-list-of-naughty-strings/
 */
const char *df_str_def[] = {
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "%s%s%s%s%s%s%s%s%s%n%s%n%n%n%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s",
    "%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n"
    "%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n",
    "bomb(){ bomb|bomb & }; bomb",
    ":1.285",
    "org.freedesktop.foo",
    "/org/freedesktop/foo",
    "xdg-open %s",
    "xdg-open ./*",
    "touch ~/blns",
    /* Strings which may be used elsewhere in code */
    "undefined",
    "undef",
    "null",
    "NULL",
    "nil",
    "NIL",
    /* Strings which can be interpreted as numeric */
    "0",
    "1",
    "1.00",
    "$1.00",
    "1/2",
    "1E2",
    "1E02",
    "1E+02",
    "-1",
    "-1.00",
    "-$1.00",
    "-1/2",
    "-1E2",
    "-1E02",
    "-1E+02",
    "1/0",
    "0/0",
    "0.00",
    "0..0",
    ".",
    "0.0.0",
    "0,00",
    "0,,0",
    ",",
    "0,0,0",
    "--1",
    "-",
    "-.",
    "-,",
    "999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999",
    "NaN",
    "Infinity",
    "-Infinity",
    /* Strings which contain common special ASCII characters (may need to be escaped) */
    ",./;'[]\-=",
    "<>?:\"{}|_+",
    "!@#$%^&*()`\"",
    /* Strings which contain common unicode symbols (e.g. smart quotes) */
    "Ω≈ç√∫˜µ≤≥÷",
    "åß∂ƒ©˙∆˚¬…æ",
    "œ∑´®†¥¨ˆøπ“‘",
    "¡™£¢∞§¶•ªº–≠",
    "¸˛Ç◊ı˜Â¯˘¿",
    "ÅÍÎÏ˝ÓÔÒÚÆ☃",
    "Œ„´‰ˇÁ¨ˆØ∏”’",
    "`⁄€‹›ﬁﬂ‡°·‚—±",
    /* Strings which contain unicode subscripts/superscripts; can cause rendering issues */
    "⁰⁴⁵",
    "₀₁₂",
    "⁰⁴⁵₀₁₂",
    /* Strings which contain two-byte characters: can cause rendering issues or character-length issues */
    "田中さんにあげて下さい",
    "パーティーへ行かないか",
    "和製漢語",
    "部落格",
    "사회과학원 어학연구소",
    "社會科學院語學研究所",
    "울란바토르",
    "𠜎𠜱𠝹𠱓𠱸𠲖𠳏",
    /* Strings which consists of Japanese-style emoticons which are popular on the web */
    "ヽ༼ຈل͜ຈ༽ﾉ ヽ༼ຈل͜ຈ༽ﾉ",
    "(｡◕ ∀ ◕｡)",
    "｀ｨ(´∀｀∩",
    "__ﾛ(,_,*)",
    "・(￣∀￣)・:*:",
    "ﾟ･✿ヾ╲(｡◕‿◕｡)╱✿･ﾟ",
    ",。・:*:・゜’( ☻ ω ☻ )。・:*:・゜’",
    "(╯°□°）╯︵ ┻━┻)  ",
    "(ﾉಥ益ಥ）ﾉ﻿ ┻━┻",
    /* Strings which contain Emoji; should be the same behavior as two-byte characters, but not always */
    "😍",
    "👩🏽",
    "👾 🙇 💁 🙅 🙆 🙋 🙎 🙍 ",
    "🐵 🙈 🙉 🙊",
    "❤️ 💔 💌 💕 💞 💓 💗 💖 💘 💝 💟 💜 💛 💚 💙",
    "✋🏿 💪🏿 👐🏿 🙌🏿 👏🏿 🙏🏿",
    "🚾 🆒 🆓 🆕 🆖 🆗 🆙 🏧",
    "0️⃣ 1️⃣ 2️⃣ 3️⃣ 4️⃣ 5️⃣ 6️⃣ 7️⃣ 8️⃣ 9️⃣ 🔟",
    /* Strings which contain unicode numbers; if the code is localized, it should see the input as numeric */
    "１２３",
    "١٢٣",
    /* Strings which contain text that should be rendered RTL if possible (e.g. Arabic, Hebrew) */
    "ثم نفس سقطت وبالتحديد،, جزيرتي باستخدام أن دنو. إذ هنا؟ الستار وتنصيب كان. أهّل ايطاليا، بريطانيا-فرنسا قد أخذ. سليمان، إتفاقية بين ما, يذكر الحدود أي بعد, معاملة بولندا، الإطلاق عل إيو.",
    "בְּרֵאשִׁית, בָּרָא אֱלֹהִים, אֵת הַשָּׁמַיִם, וְאֵת הָאָרֶץ",
    "הָיְתָהtestالصفحات التّحول",
    /* Strings which contain unicode space characters with special properties */
    "",
    "​    ",
    " ",
    "᠎",
    "　",
    "﻿",
    "␣",
    "␢",
    "␡",
    /* Strings which contain unicode with unusual properties */
    " test ",
    "⁦test⁧",
    "test",
    "test",
    "test",
    "test test test",
    "testကtest",
    "test﷐",
    /* Strings which contain "corrupted" text. */
    "Ṱ̺̺̕o͞ ̷i̲̬͇̪͙n̝̗͕v̟̜̘̦͟o̶̙̰̠kè͚̮̺̪̹̱̤ ̖t̝͕̳̣̻̪͞h̼͓̲̦̳̘̲e͇̣̰̦̬͎ ̢̼̻̱̘h͚͎͙̜̣̲ͅi̦̲̣̰̤v̻͍e̺̭̳̪̰-m̢iͅn̖̺̞̲̯̰d̵̼̟͙̩̼̘̳ ̞̥̱̳̭r̛̗̘e͙p͠r̼̞̻̭̗e̺̠̣͟s̘͇̳͍̝͉e͉̥̯̞̲͚̬͜ǹ̬͎͎̟̖͇̤t͍̬̤͓̼̭͘ͅi̪̱n͠g̴͉ ͏͉ͅc̬̟h͡a̫̻̯͘o̫̟̖͍̙̝͉s̗̦̲.̨̹͈̣",
    "̡͓̞ͅI̗̘̦͝n͇͇͙v̮̫ok̲̫̙͈i̖͙̭̹̠̞n̡̻̮̣̺g̲͈͙̭͙̬͎ ̰t͔̦h̞̲e̢̤ ͍̬̲͖f̴̘͕̣è͖ẹ̥̩l͖͔͚i͓͚̦͠n͖͍̗͓̳̮g͍ ̨o͚̪͡f̘̣̬ ̖̘͖̟͙̮c҉͔̫͖͓͇͖ͅh̵̤̣͚͔á̗̼͕ͅo̼̣̥s̱͈̺̖̦̻͢.̛̖̞̠̫̰",
    "̗̺͖̹̯͓Ṯ̤͍̥͇͈h̲́e͏͓̼̗̙̼̣͔ ͇̜̱̠͓͍ͅN͕͠e̗̱z̘̝̜̺͙p̤̺̹͍̯͚e̠̻̠͜r̨̤͍̺̖͔̖̖d̠̟̭̬̝͟i̦͖̩͓͔̤a̠̗̬͉̙n͚͜ ̻̞̰͚ͅh̵͉i̳̞v̢͇ḙ͎͟-҉̭̩̼͔m̤̭̫i͕͇̝̦n̗͙ḍ̟ ̯̲͕͞ǫ̟̯̰̲͙̻̝f ̪̰̰̗̖̭̘͘c̦͍̲̞͍̩̙ḥ͚a̮͎̟̙͜ơ̩̹͎s̤.̝̝ ҉Z̡̖̜͖̰̣͉̜a͖̰͙̬͡l̲̫̳͍̩g̡̟̼̱͚̞̬ͅo̗͜.̟",
    "̦H̬̤̗̤͝e͜ ̜̥̝̻͍̟́w̕h̖̯͓o̝͙̖͎̱̮ ҉̺̙̞̟͈W̷̼̭a̺̪͍į͈͕̭͙̯̜t̶̼̮s̘͙͖̕ ̠̫̠B̻͍͙͉̳ͅe̵h̵̬͇̫͙i̹͓̳̳̮͎̫̕n͟d̴̪̜̖ ̰͉̩͇͙̲͞ͅT͖̼͓̪͢h͏͓̮̻e̬̝̟ͅ ̤̹̝W͙̞̝͔͇͝ͅa͏͓͔̹̼̣l̴͔̰̤̟͔ḽ̫.͕",
    "Z̮̞̠͙͔ͅḀ̗̞͈̻̗Ḷ͙͎̯̹̞͓G̻O̭̗̮",
    /* Strings which contain unicode with an "upsidedown" effect */
    "˙ɐnbᴉlɐ ɐuƃɐɯ ǝɹolop ʇǝ ǝɹoqɐl ʇn ʇunpᴉpᴉɔuᴉ ɹodɯǝʇ poɯsnᴉǝ op pǝs 'ʇᴉlǝ ƃuᴉɔsᴉdᴉpɐ ɹnʇǝʇɔǝsuoɔ 'ʇǝɯɐ ʇᴉs ɹolop ɯnsdᴉ ɯǝɹo˥",
    "00˙Ɩ$-",
    /* Strings which attempt to invoke a benign script injection; shows vulnerability to XSS */
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS') />",
    "<svg><script>0<1>alert('XSS')</script> ",
    "\"><script>alert(document.title)</script>",
    "'><script>alert(document.title)</script>",
    "><script>alert(document.title)</script>",
    "</script><script>alert(document.title)</script>",
    "< / script >< script >alert(document.title)< / script >",
    " onfocus=alert(document.title) autofocus ",
    "\" onfocus=alert(document.title) autofocus ",
    "' onfocus=alert(document.title) autofocus ",
    "＜script＞alert(document.title)＜/script＞",
    "<sc<script>ript>alert('XSS')</sc</script>ript>",
    /* Strings which can cause a SQL injection if inputs are not sanitized */
    "1;DROP TABLE users",
    "1'; DROP TABLE users--",
    /* Strings which can cause user to run code on server as a privileged user */
    "/dev/null; touch /tmp/blns.fail ; echo",
    "-",
    "--",
    "--version",
    "--help",
    "$USER",
    "/dev/null; touch /tmp/blns.fail ; echo",
    "`touch /tmp/blns.fail`",
    "$(touch /tmp/blns.fail)",
    "@{[system \"touch /tmp/blns.fail\"]}",
    /* String which can reveal system files when parsed by a badly configured XML parser */
    "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><!DOCTYPE foo [ <!ELEMENT foo ANY ><!ENTITY xxe SYSTEM \"file:///etc/passwd\" >]><foo>&xxe;</foo>",
    /* Strings which can be accidentally expanded into different strings if evaluated in the wrong context */
    "$HOME",
    "$ENV{'HOME'}",
    "%d",
    "%s",
    "%*.*s",
    /* Strings which can cause user to pull in files that should not be a part of a server */
    "../../../../../../../../../../../etc/passwd%00",
    "../../../../../../../../../../../etc/hosts",
    "() { 0; }; touch /tmp/blns.shellshock1.fail;",
    /* Strings that test for known vulnerabilities */
    "() { _; } >_[$($())] { touch /tmp/blns.shellshock2.fail; }",
    "Powerلُلُصّبُلُلصّبُررً ॣ ॣh ॣ ॣ冗",
    NULL
};

#endif

