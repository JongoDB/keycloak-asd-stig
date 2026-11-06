import re,sys,json,html,time,subprocess,os
idx=json.load(open(sys.argv[1])); out=sys.argv[2]
data=json.load(open(out)) if os.path.exists(out) else {}
base="https://www.stigviewer.com/stigs/application_security_and_development/2025-09-09/finding/"
def text(h):
    t=re.sub(r'<script.*?</script>|<style.*?</style>','',h,flags=re.S)
    t=re.sub(r'<[^>]+>','\n',t); t=html.unescape(t); return re.sub(r'\n\s*\n+','\n',t)
for r in idx:
    v=r['id']
    if v in data: continue
    h=subprocess.run(['curl','-sS','--max-time','30',base+v],capture_output=True,text=True).stdout
    t=text(h)
    try:
        ov=re.search(r'\nSeverity\n(V-\d+)\n(APSC-DV-\d+)\n(SV-\S+)\n(.*?)\n(high|medium|low)\nDescription\n(.*?)\nSTIG\nDate',t,re.S)
        chk=re.search(r'\nCheck Text \(.*?_chk\)\n(.*?)\nFix Text',t,re.S)
        fix=re.search(r'\nFix Text \(\n?\S+?_fix\n?\)\n(.*?)\nSTIG Vi',t,re.S)
        data[v]={"vuln_id":v,"stig_id":ov[2],"rule_id":ov[3],"ccis":re.findall(r'CCI-\d+',ov[4]),
          "severity":ov[5],"cat":{"high":"I","medium":"II","low":"III"}[ov[5]],"title":r['title'],
          "discussion":ov[6].strip(),"check":chk[1].strip() if chk else "", "fix":fix[1].strip() if fix else ""}
    except Exception as e:
        print("FAIL",v,e,file=sys.stderr); continue
    time.sleep(0.3)
    if len(data)%25==0:
        json.dump(data,open(out,'w'),indent=1); print(len(data),flush=True)
json.dump(data,open(out,'w'),indent=1); print("done",len(data))
