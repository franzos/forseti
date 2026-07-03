# Surface d'intégration (modèles claim_email et invite)

# E-mail de revendication (claim_email.html)
claim-page-title = Revendiquer une adresse e-mail
claim-card-title = Revendiquer une adresse e-mail
claim-subtitle = Si quelqu'un a enregistré votre adresse e-mail sans jamais la vérifier, vous pouvez en prendre possession en confirmant que vous recevez du courrier à cette adresse.
claim-email-label = E-mail
claim-send-code = Envoyer le code
claim-changed-mind = Vous avez changé d'avis ?
claim-back-to-signup = Retour à l'inscription

# Confirmer la revendication (claim_email_confirm.html)
claim-confirm-page-title = Confirmer la revendication
claim-confirm-card-title = Confirmez votre code
claim-confirm-subtitle = Saisissez le code à 6 chiffres que nous venons d'envoyer. Les codes expirent après 15 minutes.
claim-confirm-code-label = Code
claim-confirm-button = Confirmer
claim-confirm-no-code = Vous n'avez pas reçu de code ?
claim-confirm-start-over = Recommencer

# Accepter l'invitation (invite/accept.html)
invite-accept-page-title = Accepter l'invitation
invite-accept-heading = Rejoindre { $org }
invite-accept-body = Vous avez été invité à rejoindre { $org } en tant que { $role }. L'invitation a été envoyée à { $email }.

# Invitation indisponible (invite/invalid.html)
invite-invalid-page-title = Invitation indisponible
invite-invalid-heading = Invitation indisponible
invite-invalid-contact = Contactez la personne qui vous a invité pour demander un nouveau lien.
invite-invalid-back = Retour au tableau de bord

# Erreurs du flux de revendication d'e-mail (définies dans Rust)
claim-error-invalid-email = Saisissez une adresse e-mail valide.
claim-error-code-expired = Le code a expiré. Recommencez.
claim-error-invalid-token = Jeton invalide. Recommencez.
claim-error-service-unavailable = Service temporairement indisponible. Réessayez dans un instant.
claim-error-too-many-attempts = Trop de codes erronés. Recommencez.
claim-error-code-mismatch = Le code ne correspond pas. Réessayez.
claim-error-no-longer-claimable = Cette adresse e-mail ne peut plus être revendiquée.
claim-error-release-failed = Nous n'avons pas pu libérer l'adresse e-mail. Contactez le support.

# Finalisation de l'invitation (définie dans Rust)
invite-error-corrupt = L'invitation est corrompue. Contactez votre administrateur.
