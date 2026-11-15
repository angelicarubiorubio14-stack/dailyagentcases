// Milo Launch Check: free client-side MVP. Everything runs in the browser; nothing is uploaded.
(function(){
  const RULES=[
    {id:'pk',sev:'high',name:'Private key block',re:/-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,fix:'Remove the key from client code, rotate it, and keep it only on your server or in a secrets manager.'},
    {id:'openai',sev:'high',name:'OpenAI API key',re:/\bsk-(?:proj-)?[A-Za-z0-9_\-]{32,}\b/g,fix:'Revoke the key at platform.openai.com, then call OpenAI only from a server route or edge function.'},
    {id:'anthropic',sev:'high',name:'Anthropic API key',re:/\bsk-ant-[A-Za-z0-9_\-]{20,}\b/g,fix:'Revoke it in the Anthropic console and move calls to a backend route.'},
    {id:'stripe',sev:'high',name:'Stripe secret/restricted key',re:/\b(?:sk|rk)_live_[0-9A-Za-z]{16,}\b/g,fix:'Roll the key in the Stripe dashboard. Only pk_live_ keys belong in the browser.'},
    {id:'aws',sev:'high',name:'AWS access key ID',re:/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,fix:'Deactivate it in AWS IAM, check CloudTrail for misuse, and use short-lived server-side credentials.'},
    {id:'gh',sev:'high',name:'GitHub token',re:/\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b/g,fix:'Revoke it under GitHub → Settings → Developer settings.'},
    {id:'slack',sev:'high',name:'Slack token',re:/\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g,fix:'Revoke the token in your Slack app settings.'},
    {id:'sendgrid',sev:'high',name:'SendGrid API key',re:/\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b/g,fix:'Delete the key in SendGrid and send email from a server route.'},
    {id:'twilio',sev:'high',name:'Twilio API key',re:/\bSK[0-9a-f]{32}\b/g,fix:'Delete the key in the Twilio console.'},
    {id:'dburl',sev:'high',name:'Database URL with password',re:/\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|rediss):\/\/[^\s:@\/"'`]+:[^\s@"'`]+@[^\s"'`]+/g,fix:'Change the database password now. Browsers should never connect to a database directly.'},
    {id:'gkey',sev:'med',name:'Google API key',re:/\bAIza[0-9A-Za-z_\-]{35}\b/g,fix:'Firebase web keys are public by design, but restrict this key to your domains and APIs in Google Cloud Console.'},
    {id:'firebase',sev:'med',name:'Firebase Realtime Database in use',re:/[a-z0-9\-]+\.firebaseio\.com|[a-z0-9\-]+\.firebasedatabase\.app/g,fix:'Open your database rules and make sure they are not ".read": true / ".write": true.'},
    {id:'supabase',sev:'low',name:'Supabase project URL',re:/https:\/\/[a-z0-9]{20}\.supabase\.co/g,fix:'Fine to expose, but confirm Row Level Security is ON for every table.'},
    {id:'pwd',sev:'med',name:'Hard-coded password or secret',re:/\b(?:password|passwd|secret|api_?key|auth_?token)\b["']?\s*[:=]\s*["'][^"'\s]{8,}["']/gi,fix:'Move this value to a server-side environment variable.'},
    {id:'pubsecret',sev:'med',name:'Secret-looking public env var',re:/\b(?:NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC)_[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|PASSWORD)[A-Z0-9_]*\b/g,fix:'Anything with a NEXT_PUBLIC_/VITE_ prefix ships to every visitor. Rename it and use it on the server only.'},
    {id:'srcmap',sev:'low',name:'Source map reference',re:/\/\/# sourceMappingURL=\S+\.map/g,fix:'Source maps reveal your original source. Turn them off in production builds unless you need them.'}
  ];
  const JWT=/\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{10,}\b/g;
  const W={high:30,med:10,low:3};
  function redact(s){return s.length<=14?s.slice(0,4)+'…':s.slice(0,8)+'…'+s.slice(-4)}
  function esc(s){return s.replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
  function b64(s){try{s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';return JSON.parse(atob(s))}catch(e){return null}}
  function scan(text){
    const out=[];
    for(const r of RULES){const m=[...new Set((text.match(r.re)||[]))];if(m.length)out.push({sev:r.sev,name:r.name,hits:m,fix:r.fix})}
    const jwts=[...new Set(text.match(JWT)||[])];
    for(const t of jwts){const p=b64(t.split('.')[1]);if(!p)continue;
      if(p.role==='service_role')out.push({sev:'high',name:'Supabase service_role key',hits:[t],fix:'This key bypasses all Row Level Security. Rotate it in Supabase → Settings → API and use it only on the server.'});
      else if(p.role==='anon')out.push({sev:'low',name:'Supabase anon key',hits:[t],fix:'Public by design. Safe only if Row Level Security is enabled with sensible policies on every table.'});
      else out.push({sev:'med',name:'JWT token embedded in code',hits:[t],fix:'Check what this token grants (claims: '+esc(Object.keys(p).slice(0,6).join(', '))+'). Long-lived tokens should not ship in client code.'});
    }
    const order={high:0,med:1,low:2};out.sort((a,b)=>order[a.sev]-order[b.sev]);return out;
  }
  function render(findings,bytes){
    const el=document.getElementById('report');
    let score=100;for(const f of findings)score-=W[f.sev];score=Math.max(0,score);
    const hi=findings.filter(f=>f.sev==='high').length;
    const verdict=hi?'Do not launch yet':score>=85?'Looks reasonable to launch':'Fix the warnings first';
    let h=`<div class="card"><div class="score">${score}/100 · ${verdict}</div><p>Scanned ${bytes.toLocaleString()} characters locally in your browser. ${findings.length} finding type(s). <span class="muted">Generated ${new Date().toLocaleString()}</span></p></div>`;
    if(!findings.length)h+=`<div class="finding pass"><b>No known secret patterns found</b>This covers common key formats only. It is not a full audit: also check database rules, auth on API routes, and rate limits.</div>`;
    for(const f of findings){h+=`<div class="finding ${f.sev}"><b>${f.sev.toUpperCase()} · ${esc(f.name)} (${f.hits.length})</b>${f.hits.slice(0,5).map(x=>'<code>'+esc(redact(x))+'</code>').join(' ')}<div>${esc(f.fix)}</div></div>`}
    h+=`<p><button class="btn ghost" onclick="window.print()">Save as one-page PDF</button></p>`;
    el.innerHTML=h;el.scrollIntoView({behavior:'smooth'});
  }
  window.MiloCheck={scan};
  document.addEventListener('DOMContentLoaded',()=>{
    const f=document.getElementById('checkForm');if(!f)return;
    const files=document.getElementById('files');
    f.addEventListener('submit',async e=>{e.preventDefault();
      let text=document.getElementById('code').value||'';
      for(const file of (files.files||[]))text+='\n'+await file.text();
      if(!text.trim()){document.getElementById('report').innerHTML='<p class="msg">Paste some code or pick files first.</p>';return}
      render(scan(text),text.length);
    });
    document.getElementById('demo').addEventListener('click',()=>{
      document.getElementById('code').value='// demo bundle (fake keys)\nconst supabaseUrl="https://abcdefghijklmnopqrst.supabase.co";\nconst key="eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UifQ.ZmFrZXNpZ25hdHVyZWZha2U";\nconst openai="sk-proj-FAKEfakeFAKEfakeFAKEfakeFAKEfake1234";\nprocess.env.NEXT_PUBLIC_STRIPE_SECRET;\n//# sourceMappingURL=main.js.map';
    });
  });
})();
