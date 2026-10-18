#!/bin/sh
# Disposable Linux container only; root provisions two distinct effective identities.
set -eu
[ "$(id -u)" = 0 ]
root=$(mktemp -d /tmp/ors-isolation.XXXXXX)
service_pid=''
cleanup() { if [ -n "$service_pid" ]; then kill -TERM "$service_pid" 2>/dev/null || true; wait "$service_pid" 2>/dev/null || true; fi; rm -rf "$root"; }
trap cleanup EXIT INT TERM
chmod 755 "$root"
mkdir "$root/custody" "$root/client" "$root/run"
chown 1000:1000 "$root/custody"
chown 1001:1001 "$root/client"
chown 1000:2000 "$root/run"
chmod 700 "$root/custody" "$root/client"
chmod 750 "$root/run"
service() { setpriv --reuid=1000 --regid=1000 --groups=2000 --no-new-privs "$@"; }
client() { setpriv --reuid=1001 --regid=1001 --groups=2000 --no-new-privs "$@"; }
service bun --no-env-file src/cli.ts init --vault-dir "$root/custody/vault" --key-file "$root/custody/master.key" --operator-file "$root/custody/operator.token" > "$root/init.json"
vault_id=$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")).vaultId)' "$root/init.json")
service bun --no-env-file src/cli.ts serve --vault-dir "$root/custody/vault" --key-file "$root/custody/master.key" --socket "$root/run/api.sock" --socket-group 2000 > "$root/service.log" 2>&1 &
service_pid=$!
node -e 'const f=require("fs");let n=0;const t=setInterval(()=>{if(f.existsSync(process.argv[1])){clearInterval(t)}else if(++n>100){process.exit(1)}},20)' "$root/run/api.sock"
service bun --no-env-file src/cli.ts token issue --socket "$root/run/api.sock" --vault-id "$vault_id" --token-file "$root/custody/operator.token" --kind service --namespace isolated --capabilities metadata,read,write,delete --expires-in 1h --out-file "$root/custody/client.token" > /dev/null
install -o 1001 -g 1001 -m 600 "$root/custody/client.token" "$root/client/service.token"
client node --input-type=module -e '
import{readFileSync}from"node:fs";import{createClient}from"/work/dist/client.js";
const[root,vaultId]=process.argv.slice(1);
for(const path of ["custody/master.key","custody/operator.token","custody/vault/vault.sqlite"]){let denied=false;try{readFileSync(`${root}/${path}`)}catch(e){denied=e.code==="EACCES"}if(!denied)throw new Error("custody boundary failed")}
const c=createClient({socketPath:`${root}/run/api.sock`,tokenFile:`${root}/client/service.token`,vaultId});const scope={namespace:"isolated",ownerUserId:"u",workspaceId:"w",consumerId:"p"};await c.put({scope,name:"probe",value:"synthetic-isolation",expectedRevision:0});if((await c.resolve({scope,selector:{name:"probe"}})).value!=="synthetic-isolation")process.exit(2);
' "$root" "$vault_id"
# A non-writable foreign-owned ancestor can still be renamed by its owner.
mkdir "$root/foreign" "$root/foreign/leaf"
chown 1002:1002 "$root/foreign"
chown 1000:1000 "$root/foreign/leaf"
chmod 755 "$root/foreign"
chmod 700 "$root/foreign/leaf"
if service bun --no-env-file src/cli.ts init --vault-dir "$root/foreign/leaf/vault" --key-file "$root/foreign/leaf/key" --operator-file "$root/foreign/leaf/token" > /dev/null 2>&1; then
    printf '%s\n' 'Foreign-owned ancestor was incorrectly admitted' >&2; exit 1
fi
node -e 'require("fs").writeFileSync("/receipts/isolation.json",JSON.stringify({serviceUid:1000,clientUid:1001,sharedGid:2000,custodyRead:"denied",socketRoundtrip:"passed",node:process.version},null,2))'
