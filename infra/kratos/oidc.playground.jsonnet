local claims = std.extVar('claims');
{
  identity: {
    traits: {
      email: if 'email' in claims && claims.email != '' then claims.email else claims.sub + '@playground.invalid',
    },
  },
}
