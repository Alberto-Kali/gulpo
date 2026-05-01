"use client";

import { useState } from "react";

type Props = {
  protocol: string;
  uri: string;
  clientPassword?: string;
  uuid?: string;
  publicKey?: string;
  shortID?: string;
};

export function ProfileActions({ protocol, uri, clientPassword, uuid, publicKey, shortID }: Props) {
  const [notice, setNotice] = useState("");

  function fallbackCopy(value: string) {
    const area = document.createElement("textarea");
    area.value = value;
    area.setAttribute("readonly", "true");
    area.style.position = "fixed";
    area.style.top = "-9999px";
    area.style.left = "-9999px";
    document.body.appendChild(area);
    area.focus();
    area.select();
    area.setSelectionRange(0, area.value.length);
    const copied = document.execCommand("copy");
    document.body.removeChild(area);
    if (!copied) {
      throw new Error("copy fallback failed");
    }
  }

  async function copy(value: string, label: string) {
    try {
      if (navigator.clipboard?.writeText && window.isSecureContext) {
        await navigator.clipboard.writeText(value);
      } else {
        fallbackCopy(value);
      }
      setNotice(`${label} copied`);
      window.setTimeout(() => setNotice(""), 1600);
    } catch {
      setNotice(`Could not copy ${label.toLowerCase()}`);
    }
  }

  return (
    <div className="profile-actions">
      <div className="actions-row">
        {clientPassword ? (
          <button className="secondary" onClick={() => void copy(clientPassword, "Password")} type="button">
            Copy Password
          </button>
        ) : null}
        {uuid ? (
          <button className="secondary" onClick={() => void copy(uuid, "UUID")} type="button">
            Copy UUID
          </button>
        ) : null}
        {publicKey ? (
          <button className="secondary" onClick={() => void copy(publicKey, "Public key")} type="button">
            Copy Public Key
          </button>
        ) : null}
        {shortID ? (
          <button className="secondary" onClick={() => void copy(shortID, "Short ID")} type="button">
            Copy Short ID
          </button>
        ) : null}
        <button className="secondary" onClick={() => void copy(uri, `${protocol} profile`)} type="button">
          Copy URI
        </button>
      </div>
      {notice ? <div className="notice compact-notice">{notice}</div> : null}
    </div>
  );
}
