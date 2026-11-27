<script lang="ts">
  import { onMount } from "svelte";
  import { ApiError, UNREACHABLE, currentSession, login, logout } from "./api";
  import type { SessionInfo } from "./api";
  import { refusalMessage } from "./messages";

  let session = $state<SessionInfo | null>(null);
  let ready = $state(false);
  let busy = $state(false);
  let error = $state<string | null>(null);
  let username = $state("");
  let password = $state("");
  let totp = $state("");
  let clientVersion = $state<number | null>(null);
  let clientError = $state(false);

  // The WebAssembly client, loaded once a session is open.
  $effect(() => {
    if (session !== null && clientVersion === null && !clientError) {
      import("./client")
        .then((m) => m.loadClient())
        .then((v) => {
          clientVersion = v;
        })
        .catch(() => {
          clientError = true;
        });
    }
  });

  function codeOf(e: unknown): string {
    return e instanceof ApiError ? e.code : UNREACHABLE;
  }

  onMount(async () => {
    try {
      session = await currentSession();
    } catch (e) {
      error = codeOf(e);
    } finally {
      ready = true;
    }
  });

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (busy) {
      return;
    }
    busy = true;
    error = null;
    try {
      session = await login(username.trim(), password, totp.trim());
    } catch (e) {
      error = codeOf(e);
    } finally {
      // The factors never outlive the attempt.
      password = "";
      totp = "";
      busy = false;
    }
  }

  async function signOut() {
    busy = true;
    error = null;
    try {
      await logout();
      session = null;
    } catch (e) {
      error = codeOf(e);
    } finally {
      busy = false;
    }
  }
</script>

<a class="skip" href="#contenu">Aller au contenu</a>
<header class="banner">
  <svg class="symbol" viewBox="0 0 128 128" aria-hidden="true" focusable="false">
    <path class="arc" d="M83.08 90.53 A36 36 0 1 0 44.92 90.53" />
    <rect class="bar" x="59" y="70" width="10" height="38" rx="5" />
  </svg>
  <span class="name">ostena</span>
</header>

<main id="contenu" tabindex="-1">
  {#if !ready}
    <p class="status" role="status">Chargement…</p>
  {:else if session}
    <section class="card" aria-labelledby="titre-session">
      <h1 id="titre-session">Connecté</h1>
      <p>
        Vous êtes connecté en tant que <strong>{session.display_name}</strong>
        (<span class="mono">{session.username}</span>).
      </p>
      <p class="status" role="status">
        {#if clientVersion !== null}
          Client de session prêt (protocole ostena-frame v{clientVersion}).
        {:else if clientError}
          Client de session indisponible. <span class="code">(PORTAL-E002)</span>
        {:else}
          Chargement du client de session…
        {/if}
      </p>
      <button type="button" onclick={signOut} disabled={busy}>Se déconnecter</button>
    </section>
  {:else}
    <section class="card" aria-labelledby="titre-connexion">
      <h1 id="titre-connexion">Connexion au bastion</h1>
      <form onsubmit={submit} novalidate={false}>
        <div class="field">
          <label for="username">Identifiant</label>
          <input
            id="username"
            name="username"
            autocomplete="username"
            autocapitalize="none"
            spellcheck="false"
            required
            maxlength="64"
            bind:value={username}
            aria-describedby={error ? "erreur" : undefined}
          />
        </div>
        <div class="field">
          <label for="password">Mot de passe</label>
          <input
            id="password"
            name="password"
            type="password"
            autocomplete="current-password"
            required
            maxlength="1024"
            bind:value={password}
            aria-describedby={error ? "erreur" : undefined}
          />
        </div>
        <div class="field">
          <label for="totp">Code à usage unique</label>
          <input
            id="totp"
            name="totp"
            autocomplete="one-time-code"
            inputmode="numeric"
            pattern="[0-9]{'{'}6{'}'}"
            required
            maxlength="6"
            bind:value={totp}
            aria-describedby={error ? "erreur totp-aide" : "totp-aide"}
          />
          <p id="totp-aide" class="hint">Six chiffres, affichés par votre application d'authentification.</p>
        </div>
        {#if error}
          <p id="erreur" class="error" role="alert">
            {refusalMessage(error)} <span class="code">({error})</span>
          </p>
        {/if}
        <button type="submit" disabled={busy}>Se connecter</button>
      </form>
    </section>
  {/if}
  {#if ready && session && error}
    <p class="error" role="alert">
      {refusalMessage(error)} <span class="code">({error})</span>
    </p>
  {/if}
</main>
