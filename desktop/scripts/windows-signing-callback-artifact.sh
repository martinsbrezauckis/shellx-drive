#!/bin/bash
# Descriptor-bound staging and restoration for the pinned signing callback.

release_callback_file_helper() {
  release_helper_verify_identity CALLBACK_FILE || return 1
  release_helper_path CALLBACK_FILE
}

release_callback_capture_source_artifact() {
  local source="$1" alias="${2:--}" helper
  helper="$(release_callback_file_helper)" || return 1
  RELEASE_CALLBACK_SOURCE_ALIAS="$alias"
  read -r RELEASE_CALLBACK_SOURCE_ID RELEASE_CALLBACK_UNSIGNED_SHA256 \
    < <("$NODE_BIN" "$helper" inspect "$source" "$alias") \
    || { echo "callback signing could not admit the source handle" >&2; return 1; }
}

release_callback_stage_artifact() {
  local source="$1" stage="$2" helper
  helper="$(release_callback_file_helper)" || return 1
  read -r admitted_id admitted_digest RELEASE_CALLBACK_STAGE_ID \
    < <("$NODE_BIN" "$helper" stage "$source" "$stage" \
      "$RELEASE_CALLBACK_SOURCE_ID" "$RELEASE_CALLBACK_UNSIGNED_SHA256" \
      "$RELEASE_CALLBACK_SOURCE_ALIAS") \
    || { echo "callback signing could not pin the unsigned source handle" >&2; return 1; }
  [[ "$admitted_id" == "$RELEASE_CALLBACK_SOURCE_ID" \
    && "$admitted_digest" == "$RELEASE_CALLBACK_UNSIGNED_SHA256" ]]
}

release_callback_assert_unsigned_stage() {
  local stage="$1" helper
  helper="$(release_callback_file_helper)" || return 1
  "$NODE_BIN" "$helper" verify-stage \
    "$stage" "$RELEASE_CALLBACK_UNSIGNED_SHA256" "$RELEASE_CALLBACK_STAGE_ID"
}

release_callback_restore_artifact() {
  local source="$1" stage="$2" label="$3" helper
  helper="$(release_callback_file_helper)" || return 1
  "$NODE_BIN" "$helper" restore "$source" "$stage" \
    "$RELEASE_CALLBACK_SOURCE_ID" "$RELEASE_CALLBACK_UNSIGNED_SHA256" "$RELEASE_CALLBACK_STAGE_ID" \
    "$RELEASE_CALLBACK_SOURCE_ALIAS" \
    || { echo "$label source handle or unsigned bytes changed during signing" >&2; return 1; }
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  echo "usage: source $0 from windows-artifact-sign-command.sh" >&2
  exit 2
fi
