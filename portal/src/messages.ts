// Texts of the portal. French only until the i18n of PR 16, which adds the
// English catalogue with the same keys.

const REFUSALS: Record<string, string> = {
  "AUTH-E001": "Identifiant, mot de passe ou code à usage unique incorrect.",
  "AUTH-E002": "Trop de tentatives depuis ce poste. Réessayez dans une minute.",
  "WEB-E001": "Votre session a expiré. Reconnectez-vous.",
  "WEB-E002": "Requête refusée : origine inattendue.",
  "WEB-E003": "Requête refusée : requête intersite.",
  "WEB-E006": "Requête refusée : contenu invalide.",
  "PORTAL-E001": "Le bastion est injoignable. Réessayez plus tard.",
  "PORTAL-E002": "Le client de session n'a pas pu être chargé.",
};

/** The message shown for a refusal code; the code is always shown too. */
export function refusalMessage(code: string): string {
  return REFUSALS[code] ?? "La demande a été refusée.";
}
