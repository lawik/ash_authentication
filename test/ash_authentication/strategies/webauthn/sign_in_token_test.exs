# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.SignInTokenTest do
  @moduledoc """
  The token a ceremony answers with is only good for one exchange through
  `sign_in_with_token`, so it lives for `sign_in_token_lifetime`, not for as
  long as a session token.
  """
  use DataCase, async: false

  alias AshAuthentication.{Info, Jwt, TokenResource}
  alias AshAuthentication.Strategy.WebAuthn.Actions
  alias AshAuthentication.Test.WebAuthnCeremony

  @moduletag feature: :webauthn

  setup do
    %{strategy: Info.strategy!(Example.UserWithWebAuthnNoIdentity, :webauthn)}
  end

  test "defaults to a minute, stored in seconds", %{strategy: strategy} do
    assert strategy.sign_in_token_lifetime == 60
  end

  test "register, sign_in and verify answer with a short-lived sign-in token", %{
    strategy: strategy
  } do
    {{:ok, registered}, passkey} = WebAuthnCeremony.register(strategy)
    assert_short_lived_sign_in_token(registered.__metadata__.token, strategy)

    {:ok, signed_in} = WebAuthnCeremony.sign_in(strategy, passkey)
    assert_short_lived_sign_in_token(signed_in.__metadata__.token, strategy)

    {:ok, verified} = WebAuthnCeremony.verify(strategy, registered, passkey)
    assert_short_lived_sign_in_token(verified.__metadata__.token, strategy)
  end

  test "the lifetime is the strategy's", %{strategy: strategy} do
    strategy = %{strategy | sign_in_token_lifetime: 5}
    {{:ok, _registered}, passkey} = WebAuthnCeremony.register(strategy)
    {:ok, signed_in} = WebAuthnCeremony.sign_in(strategy, passkey)

    {:ok, %{"iat" => iat, "exp" => exp}} = Jwt.peek(signed_in.__metadata__.token)
    assert exp - iat == 5
  end

  test "sign_in's token is stored under the purpose it claims", %{strategy: strategy} do
    {{:ok, _registered}, passkey} = WebAuthnCeremony.register(strategy)
    {:ok, signed_in} = WebAuthnCeremony.sign_in(strategy, passkey)

    assert {:ok, [stored]} =
             TokenResource.Actions.get_token(Example.Token, %{
               "token" => signed_in.__metadata__.token
             })

    assert stored.purpose == "sign_in"
  end

  test "the session token it is exchanged for keeps the resource's lifetime", %{
    strategy: strategy
  } do
    {{:ok, _registered}, passkey} = WebAuthnCeremony.register(strategy)
    {:ok, signed_in} = WebAuthnCeremony.sign_in(strategy, passkey)

    {:ok, session} =
      Actions.sign_in_with_token(strategy, %{"token" => signed_in.__metadata__.token}, [])

    {:ok, %{"iat" => iat, "exp" => exp, "purpose" => "user"}} =
      Jwt.peek(session.__metadata__.token)

    assert exp - iat > strategy.sign_in_token_lifetime
  end

  defp assert_short_lived_sign_in_token(token, strategy) do
    {:ok, %{"iat" => iat, "exp" => exp, "purpose" => "sign_in"}} = Jwt.peek(token)
    assert exp - iat == strategy.sign_in_token_lifetime
  end
end
