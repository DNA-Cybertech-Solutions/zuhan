package extract

import "strings"

// validTLD is a pragmatic allow-list: every country-code TLD plus the
// generic TLDs that actually show up in threat intel. Anything else
// ("kernel32.dll", "config.json") is treated as a file name, not a domain.
var validTLD = set(`
ac ad ae af ag ai al am ao aq ar as at au aw ax az ba bb bd be bf bg bh bi bj bm bn bo br bs bt bw by bz
ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg er es et eu fi fj fk fm
fo fr ga gd ge gf gg gh gi gl gm gn gp gq gr gs gt gu gw gy hk hm hn hr ht hu id ie il im in io iq ir is it
je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mg mh mk ml mm mn
mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps
pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st su sv sx sy sz tc td tf tg th tj
tk tl tm tn to tr tt tv tw tz ua ug uk us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw
com net org info biz edu gov mil int name pro mobi asia tel travel jobs cat coop aero museum
app dev page new how xyz top site online club shop store live life world today tech space website icu buzz
cloud work link click download win bid loan racing review stream party trade date faith science men
accountant cricket webcam gdn kim ltd vip fun host press monster rest bar cyou sbs cfd lol best blog news
email solutions services support network digital agency company group global center systems software
expert media studio design art photo pics wang ren run zone guru ninja rocks one tokyo moscow berlin
london nyc paris amsterdam bond quest uno ooo mom beauty hair skin makeup boats yachts autos homes
motorcycles lat cam surf fit casino bet games game poker porn sex xxx adult tube video cash money finance
financial capital fund investments credit loans tax bank insurance market markets exchange trading
google microsoft apple amazon azure goog onion
`)

// fileExt holds TLDs that collide with very common file extensions and are
// far more likely to be file names in a dump than real domains.
var fileExt = set(`md py sh rs so zip mov ps`)

func set(s string) map[string]bool {
	m := map[string]bool{}
	for _, f := range strings.Fields(s) {
		m[f] = true
	}
	return m
}
