# ZYEPAM INFO, vèsyon sekirite

## Sa ki chanje
- Otantifikasyon fèt sou sèvè a. Pa gen modpas admin oswa jounalis nan JavaScript navigatè a.
- Modpas yo estoke kòm hash bcrypt nan PostgreSQL.
- Sesyon yo itilize cookie HttpOnly, Secure sou Railway, SameSite Strict, ak PostgreSQL session store.
- Limit tantativ koneksyon: 8 tantativ pa 15 minit.
- Jounalis pa ka kreye oswa efase lòt kont.
- Kle ImgBB a rete sou sèvè a, nan Railway Variable `IMGBB_API_KEY`.
- Upload imaj limite a 5 MB ak fòma JPEG, PNG, WEBP oswa GIF.
- Done atik yo ak kont jounalis yo rete nan PostgreSQL.
- Rann tèks atik yo kòm tèks olye yo entèprete yo kòm HTML.

## Railway Variables obligatwa
- `DATABASE_URL`: deja egziste sou Railway.
- `ADMIN_USERNAME`: username Super Admin lan.
- `ADMIN_PASSWORD`: nouvo modpas Super Admin, omwen 12 karaktè.
- `SESSION_SECRET`: sekrè o aza ki long, omwen 64 karaktè.
- `IMGBB_API_KEY`: nouvo kle ImgBB apre ansyen kle a revoke.

`PORT` ak `NODE_ENV` ka rete jan Railway jere yo.

## Enstalasyon
Railway dwe sèvi ak kòmand `npm start`. Li pral enstale depandans yo selon `package.json`.
Mete `Root Directory` sou rasin repository a. Fichye HTML yo nan `public/`.

Lè aplikasyon an demare, li kreye tab PostgreSQL yo otomatikman. Si pa gen kont admin ki gen username `ADMIN_USERNAME`, li kreye kont lan avèk `ADMIN_PASSWORD` epi li estoke hash bcrypt la. Sou chak demaraj, li mete hash modpas Super Admin lan ajou selon `ADMIN_PASSWORD`. Sa pèmèt ou chanje modpas la nan Railway Variables epi redeplwaye pou aktive l.

## Enpòtan anvan deplwaman
1. Revoke ansyen kle ImgBB ki te nan ansyen `login.html`, epi mete yon nouvo kle nan Railway.
2. Chanje modpas Super Admin ki te ekspoze a. Mete nouvo username/modpas nan Railway Variables.
3. Ajoute `SESSION_SECRET` nan Railway Variables anvan deplwaman. Sèvis la pap demare an production san li.
4. Fè backup PostgreSQL anvan deplwaman.
5. Apre deplwaman, teste `/api/health`, koneksyon admin, kreye yon jounalis, pibliye yon atik, logout, epi verifye aksè piblik.

## Done ansyen localStorage
Ansyen kont jounalis ak atik ki te nan localStorage navigatè a pa transfere otomatikman. Yo te lokal sou aparèy/navigatè kote yo te kreye a. Atik default ki deja nan HTML yo rete disponib.
