#!/usr/bin/env bash
# Capture raw Kratos self-service flow bodies (`GET /self-service/<kind>/flows?id=`)
# from the running playground into this directory, one file per flow state.
# Uses throwaway identities. Live secrets (CSRF tokens, TOTP secret and QR,
# lookup codes) are replaced with fixed placeholders of the same shape.
#
# Requires curl, jq and oathtool on PATH:
#   guix shell curl jq oath-toolkit -- tests/fixtures/kratos_flows/capture.sh
set -euo pipefail

K="${KRATOS_PUBLIC_URL:-http://localhost:4433}"
KA="${KRATOS_ADMIN_URL:-http://localhost:4434}"
MAIL="${MAILCRAB_URL:-http://127.0.0.1:4436}"
OUT="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
PASSWORD='fixture-Pw-7h2k9q-correct'

log() { echo "capture: $*" >&2; }

new_email() { echo "fixture-$1-$(date +%s%N | tail -c 9)@example.com"; }

# init <jar> <kind> [query] -> flow id
init() {
	local jar="$1" kind="$2" query="${3:-}"
	curl -sS -c "$jar" -b "$jar" -H 'Accept: application/json' \
		"$K/self-service/$kind/browser$query" >"$WORK/init.json"
	jq -r '.id // empty' "$WORK/init.json"
}

fetch() {
	local jar="$1" kind="$2" id="$3"
	curl -sS -b "$jar" "$K/self-service/$kind/flows?id=$id"
}

csrf_of() { jq -r '[.ui.nodes[] | select(.attributes.name == "csrf_token") | .attributes.value][0]'; }

# submit <jar> <kind> <id> <field=value>... ; body in $WORK/last.json, prints status
submit() {
	local jar="$1" kind="$2" id="$3"
	shift 3
	local csrf args=()
	csrf="$(fetch "$jar" "$kind" "$id" | csrf_of)"
	for kv in "$@"; do args+=(--data-urlencode "$kv"); done
	curl -sS -c "$jar" -b "$jar" -H 'Accept: application/json' \
		-o "$WORK/last.json" -w '%{http_code}' \
		--data-urlencode "csrf_token=$csrf" "${args[@]}" \
		"$K/self-service/$kind?flow=$id"
}

scrub() {
	jq '
	  def fake($i): "fake" + (if $i < 10 then "0" else "" end) + ($i | tostring) + "aa";
	  def fake_codes:
	    .context.secrets |= [to_entries[] | .key as $i | .value
	      | if type == "object" then
	          (if has("text") then .text = fake($i) else . end)
	          | (if .context.secret then .context.secret = fake($i) else . end)
	        else fake($i) end]
	    | .text = ([.context.secrets[] | if type == "object" then (.text // .context.secret) else . end]
	        | join(", "));
	  (.ui.nodes[]? | select(.attributes.name == "csrf_token") | .attributes.value)
	    |= "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	  | (.ui.nodes[]? | select(.attributes.id == "totp_qr") | .attributes.src)
	    |= "data:image/png;base64,iVBORw0KGgo="
	  | (.ui.nodes[]? | select(.attributes.id == "totp_secret_key") | .attributes.text)
	    |= (.text = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	        | if .context.secret then .context.secret = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" else . end)
	  | (.ui.nodes[]? | select(.attributes.id == "lookup_secret_codes") | .attributes.text)
	    |= (if (.context.secrets | type) == "array" then fake_codes else . end)
	'
}

save() {
	local name="$1" jar="$2" kind="$3" id="$4"
	fetch "$jar" "$kind" "$id" | scrub >"$OUT/$name.json"
	log "$name: state=$(jq -r .state "$OUT/$name.json")"
}

create_identity() {
	local email="$1" verified="$2"
	curl -sS -X POST "$KA/admin/identities" -H 'Content-Type: application/json' \
		-d "$(jq -n --arg e "$email" --arg p "$PASSWORD" --argjson v "$verified" '{
			schema_id: "default",
			traits: { email: $e, name: { first: "Fixture", last: "User" } },
			verifiable_addresses: [{ value: $e, verified: $v, via: "email",
				status: (if $v then "completed" else "pending" end) }],
			credentials: { password: { config: { password: $p } } }
		}')" | jq -r .id
}

password_login() {
	local jar="$1" email="$2" id status
	id="$(init "$jar" login)"
	status="$(submit "$jar" login "$id" "identifier=$email" "password=$PASSWORD" method=password)"
	log "password login $email: $status"
}

# mail_code <email> <n>: code from the newest mail once <n> mails reached <email>.
mail_code() {
	local email="$1" n="$2" mid
	for _ in $(seq 1 20); do
		mid="$(curl -sS "$MAIL/api/messages" | jq -r --arg e "$email" --argjson n "$n" \
			'[.[] | select(any(.to[]; .email == $e))] | sort_by(.time)
			 | if length >= $n then last.id else empty end')"
		if [ -n "$mid" ]; then
			curl -sS "$MAIL/api/message/$mid" | jq -r '.text // .html' | grep -oE '\b[0-9]{6}\b' | head -1
			return
		fi
		sleep 1
	done
	echo "no mail for $email" >&2
	return 1
}

# Wait until at least 3 s into a fresh 30 s step, so a code stays valid for the next calls.
fresh_step() {
	local s=$(($(date +%s) % 30))
	if [ "$s" -gt 3 ]; then sleep $((33 - s)); fi
}

totp() { oathtool --totp -b "$1"; }

whoami_aal() {
	curl -sS -b "$1" -o "$WORK/whoami.json" -w '%{http_code}' "$K/sessions/whoami"
	echo " aal=$(jq -r '.authenticator_assurance_level // .error.id // empty' "$WORK/whoami.json")"
}

# --- login ---------------------------------------------------------------
email="$(new_email login)"
create_identity "$email" true >/dev/null
jar="$WORK/login"
id="$(init "$jar" login)"
save login "$jar" login "$id"
submit "$jar" login "$id" "identifier=$email" "password=wrong-password" method=password >/dev/null
save login_invalid_credentials "$jar" login "$id"
password_login "$jar" "$email"
id="$(init "$jar" login '?aal=aal2')"
if [ -n "$id" ]; then save login_aal2_no_second_factor "$jar" login "$id"; else log "aal2 init without 2FA: $(head -c 300 "$WORK/init.json")"; fi
id="$(init "$jar" login '?refresh=true')"
save login_refresh "$jar" login "$id"

# --- registration --------------------------------------------------------
reg_email="$(new_email reg)"
jar="$WORK/reg"
id="$(init "$jar" registration)"
save registration_profile "$jar" registration "$id"
status="$(submit "$jar" registration "$id" "traits.email=$reg_email" \
	"traits.name.first=Fixture" "traits.name.last=User" method=profile)"
log "registration profile submit: $status"
save registration_password "$jar" registration "$id"
status="$(submit "$jar" registration "$id" "traits.email=$reg_email" \
	"traits.name.first=Fixture" "traits.name.last=User" "password=$PASSWORD" method=password)"
log "registration password submit: $status"
mail_code "$reg_email" 1 >/dev/null

# --- verification --------------------------------------------------------
jar="$WORK/verify"
id="$(init "$jar" verification)"
save verification_choose_method "$jar" verification "$id"
status="$(submit "$jar" verification "$id" "email=$reg_email" method=code)"
log "verification email submit: $status"
save verification_sent_email "$jar" verification "$id"
code="$(mail_code "$reg_email" 2)"
status="$(submit "$jar" verification "$id" "code=$code" method=code)"
log "verification code submit: $status"
save verification_passed_challenge "$jar" verification "$id"

# --- recovery ------------------------------------------------------------
rec_email="$(new_email recovery)"
create_identity "$rec_email" true >/dev/null
jar="$WORK/recovery"
id="$(init "$jar" recovery)"
save recovery_choose_method "$jar" recovery "$id"
status="$(submit "$jar" recovery "$id" "email=$rec_email" method=code)"
log "recovery email submit: $status"
save recovery_sent_email "$jar" recovery "$id"
code="$(mail_code "$rec_email" 1)"
status="$(submit "$jar" recovery "$id" "code=$code" method=code)"
log "recovery code submit: $status"
handoff="$(jq -r '.redirect_browser_to // empty' "$WORK/last.json" | sed -n 's/.*[?&]flow=\([^&]*\).*/\1/p')"
save recovery_passed_challenge "$jar" recovery "$id"
if [ -n "$handoff" ]; then save settings_recovery_handoff "$jar" settings "$handoff"; fi

# --- settings and second factors ----------------------------------------
mfa_email="$(new_email mfa)"
mfa_id="$(create_identity "$mfa_email" true)"
jar="$WORK/mfa"
password_login "$jar" "$mfa_email"
id="$(init "$jar" settings)"
save settings_fresh "$jar" settings "$id"
secret="$(fetch "$jar" settings "$id" | jq -r '.ui.nodes[] | select(.attributes.id == "totp_secret_key") | .attributes.text.text')"
status="$(submit "$jar" settings "$id" totp_code=000000 method=totp)"
log "settings wrong totp submit: $status"
save settings_totp_pending "$jar" settings "$id"
fresh_step
status="$(submit "$jar" settings "$id" "totp_code=$(totp "$secret")" method=totp)"
log "settings totp enrol submit: $status"
save settings_totp_enrolled_submit "$jar" settings "$id"
log "whoami after enrol: $(whoami_aal "$jar")"

id="$(init "$jar" settings)"
if [ -z "$id" ]; then
	log "settings after enrol needs step-up: $(head -c 300 "$WORK/init.json")"
	fresh_step
	sid="$(init "$jar" login '?aal=aal2')"
	log "step-up: $(submit "$jar" login "$sid" "totp_code=$(totp "$secret")" method=totp)"
	id="$(init "$jar" settings)"
fi
save settings_totp_enrolled "$jar" settings "$id"

jar2="$WORK/aal2"
password_login "$jar2" "$mfa_email"
sid="$(init "$jar2" login '?aal=aal2')"
save login_aal2_totp "$jar2" login "$sid"

status="$(submit "$jar" settings "$id" lookup_secret_regenerate=true method=lookup_secret)"
log "lookup regenerate submit: $status"
save settings_lookup_generated "$jar" settings "$id"
status="$(submit "$jar" settings "$id" lookup_secret_confirm=true method=lookup_secret)"
log "lookup confirm submit: $status"
save settings_lookup_confirmed_submit "$jar" settings "$id"
id="$(init "$jar" settings)"
save settings_lookup_confirmed "$jar" settings "$id"
status="$(submit "$jar" settings "$id" lookup_secret_reveal=true method=lookup_secret)"
log "lookup reveal submit: $status"
save settings_lookup_revealed "$jar" settings "$id"

jar3="$WORK/aal2-lookup"
password_login "$jar3" "$mfa_email"
sid="$(init "$jar3" login '?aal=aal2')"
save login_aal2_totp_lookup "$jar3" login "$sid"

# --- probes ---------------------------------------------------------------
# (a) one TOTP code on two fresh AAL1 sessions within one step.
pa="$WORK/probe-a1"
pb="$WORK/probe-a2"
password_login "$pa" "$mfa_email"
password_login "$pb" "$mfa_email"
fa="$(init "$pa" login '?aal=aal2')"
fb="$(init "$pb" login '?aal=aal2')"
fresh_step
code="$(totp "$secret")"
sa="$(submit "$pa" login "$fa" "totp_code=$code" method=totp)"
ma="$(jq -c '[.ui.messages[]?.id, (.ui.nodes[]?.messages[]?.id)] // []' "$WORK/last.json" 2>/dev/null || true)"
sb="$(submit "$pb" login "$fb" "totp_code=$code" method=totp)"
mb="$(jq -c '[.ui.messages[]?.id, (.ui.nodes[]?.messages[]?.id)] // []' "$WORK/last.json" 2>/dev/null || true)"
echo "PROBE A: identity $mfa_id step $(($(date +%s) / 30))"
echo "PROBE A: first  submit status=$sa messages=$ma whoami=$(whoami_aal "$pa")"
echo "PROBE A: second submit status=$sb messages=$mb whoami=$(whoami_aal "$pb")"

# (b) password refresh on an AAL2 session.
echo "PROBE B: before refresh whoami=$(whoami_aal "$pa") authenticated_at=$(jq -r .authenticated_at "$WORK/whoami.json")"
rid="$(init "$pa" login '?refresh=true')"
save login_refresh_aal2 "$pa" login "$rid"
sleep 2
sr="$(submit "$pa" login "$rid" "identifier=$mfa_email" "password=$PASSWORD" method=password)"
echo "PROBE B: refresh submit status=$sr"
echo "PROBE B: after refresh whoami=$(whoami_aal "$pa") authenticated_at=$(jq -r .authenticated_at "$WORK/whoami.json") methods=$(jq -c '[.authentication_methods[] | {method, aal, completed_at}]' "$WORK/whoami.json")"
