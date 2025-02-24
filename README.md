# JWT Key Management for .NET - Generate and auto rotate Cryptographic Keys for your Jwt (jws) / Jwe

One of the biggest problem at Key Management is: How to distribute keys in a security way. HMAC relies on sharing the key between many projects. To accomplish it `NetDevPack.Security.Jwt` use Public Key Cryptosystem to generate your keys. So you can share you public key at `https://<your_api_adrress>/jwks`!  

<p align="center">
    <img alt="read before" src="docs/important.png" />
</p>

## Are you creating Jwt like this?
<p align="center">
    <img alt="read before" src="docs/code.png" />
</p>


## Let me tell you: You have a problem.

------------------
<br>

![Nuget](https://img.shields.io/nuget/v/NetDevPack.Security.Jwt)![coverage](https://img.shields.io/badge/coverage-93%25-green)[![NetDevPack - MASTER Publish](https://github.com/NetDevPack/Security.Jwt/actions/workflows/publish.yml/badge.svg)](https://github.com/NetDevPack/Security.Jwt/actions/workflows/publish.yml)

The goal of this project is to help your application security by Managing your JWT.

* Auto create RSA or ECDsa keys
* Support for JWE
* Support public `jwks_uri` endpoint with your public key in JWKS format (Support for JWS and JWE)
* Extensions for your client API's to consume the JWKS endpoint. See more at [NetDevack.Security.JwtExtensions](https://github.com/NetDevPack/Security.JwtExtensions)
* Auto rotate key every 90 days (Following NIST Best current practices for Public Key Rotation)
* Remove old private keys after key rotation (NIST Recommendations)
* Use recommended settings for RSA & ECDSA (RFC 7518 Recommendations)
* Uses random number generator to generate keys for JWE with AES CBC (dotnet does not support RSA-OAEP with Aes128GCM)
* By default Save keys in same room of ASP.NET DataProtection (The same place where ASP.NET save the keys to to cryptograph MVC cookies)

It generates Keys way better with RSA and ECDsa algorithms. Which is most recommended by [RFC 7518](https://datatracker.ietf.org/doc/html/rfc7518).

## Token Validation

```c#

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = "https://www.devstore.academy",
        ValidAudience = "NetDevPack.Security.Jwt.AspNet"
    };
});
builder.Services.AddAuthorization();
builder.Services.AddJwksManager().UseJwtValidation();
```

## Generating Tokens:

```c#

public AuthController(IJwtService jwtService)
{
    _jwtService = jwtService;
}

private string GenerateToken(User user)
{
    var key = _jwtService.GetCurrentSigningCredentials(); // (ECDsa or RSA) auto generated key
 
    var handler = new JsonWebTokenHandler();
    var now = DateTime.Now;
    var descriptor = new SecurityTokenDescriptor
    {
        Issuer = "https://www.devstore.academy", // <- Your website
        Audience = "NetDevPack.Security.Jwt.AspNet",
        IssuedAt = now,
        NotBefore = now,
        Expires = now.AddMinutes(60),
        Subject = new ClaimsIdentity(FakeClaims.GenerateClaim().Generate(5)),
        SigningCredentials = await service.GetCurrentSigningCredentials()
    };
    return tokenHandler.WriteToken(token);
}
```

<p align="center">
    <img width="100px" src="https://jpproject.blob.core.windows.net/images/helldog-site.png" />
</p>

## Table of Contents ##

- [JWT Key Management for .NET - Generate and auto rotate Cryptographic Keys for your Jwt](#jwt-key-management-for-net---generate-and-auto-rotate-cryptographic-keys-for-your-jwt)
  - [Are you creating Jwt like this?](#are-you-creating-jwt-like-this)
  - [Let me tell you: You have a problem.](#let-me-tell-you-you-have-a-problem)
  - [Generating Tokens:](#generating-tokens)
  - [Token Validation](#token-validation)
  - [Table of Contents](#table-of-contents)
- [🛡️ What is](#️-what-is)
- [ℹ️ Installing](#ℹ️-installing)
- [❤️ Token Generation](#️-token-generation)
- [✔️ Token Validation (Jws)](#️-token-validation-jws)
- [⛅ Multiple API's - Use Jwks](#-multiple-apis---use-jwks)
    - [Identity API (Who emits the token)](#identity-api-who-emits-the-token)
  - [Client API](#client-api)
- [💾 Storage](#-storage)
  - [Database](#database)
  - [File system](#file-system)
- [Samples](#samples)
- [Changing Algorithm](#changing-algorithm)
  - [Jws](#jws)
  - [Jwe](#jwe)
- [IdentityServer4 - Auto jwks_uri Management](#identityserver4---auto-jwks_uri-management)
- [Why](#why)
  - [Load Balance scenarios](#load-balance-scenarios)
  - [Best practices](#best-practices)
- [License](#license)

------------------

# 🛡️ What is


The JSON Web Key Set (JWKS) is a collection of public keys used for verifying JSON Web Tokens (JWTs) issued by an authorization server. This component's primary objective is to provide a centralized storage and key rotation for your JWKs while adhering to best practices in JWK generation. It features a plugin for IdentityServer4, enabling automatic rotation of the jwks_uri every 90 days and seamless management of your jwks_uri.

If your API or OAuth 2.0 is deployed under a Load Balancer in Kubernetes or Docker Swarm, this component is essential. Its functionality is similar to the DataProtection Key in ASP.NET Core.

This component generates, stores, and manages your JWKs while maintaining a centralized storage accessible across instances. By default, a new key is generated every three months.

You can expose your JWKs through a JWKS endpoint and share them with your APIs.

# ℹ️ Installing

To install `NetDevPack.Security.Jwt` in your API, use the following command in the NuGet Package Manager console:

```bash
Install-Package NetDevPack.Security.Jwt
```

Alternatively, you can use the .NET Core command line interface:

```
dotnet add package NetDevPack.Security.Jwt
```

Next, modify the Configure method in your `Startup.cs` or `program.cs` file:

```c#
builder.Services.AddJwksManager().UseJwtValidation();
```

# ❤️ Token Generation

In most cases, when we say JWT, we're actually referring to JWS.


```c#
public AuthController(IJwtService jwtService)
{
    _jwtService = jwtService;
}

private string GenerateToken(User user)
{
    var tokenHandler = new JwtSecurityTokenHandler();
    var currentIssuer = $"{ControllerContext.HttpContext.Request.Scheme}://{ControllerContext.HttpContext.Request.Host}";

    var key = _jwtService.GetCurrentSigningCredentials(); // (ECDsa or RSA) auto generated key
    var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
    {
        Issuer = currentIssuer,
        Subject = identityClaims,
        Expires = DateTime.UtcNow.AddHours(1),
        SigningCredentials = key
    });
    return tokenHandler.WriteToken(token);
}
```

# ✔️ Token Validation (JWS)

Utilize the same service to obtain the current key and validate the token..

```csharp

public AuthController(IJwtService jwtService)
{
    _jwtService = jwtService;
}

private string ValidateToken(string jwt)
{
    var handler = new JsonWebTokenHandler();
    var currentIssuer = $"{ControllerContext.HttpContext.Request.Scheme}://{ControllerContext.HttpContext.Request.Host}";

    var result = handler.ValidateToken(jwt,
        new TokenValidationParameters
        {
            ValidIssuer = currentIssuer,
            SigningCredentials = _jwtService.GetCurrentSigningCredentials()
        });
    
    result.IsValid.Should().BeTrue();
}
```

# ⛅ Multiple API's - Use Jwks

A major challenge in key management is securely distributing keys. HMAC depends on sharing a key among multiple projects. To address this, `NetDevPack.Security.Jwt` employs a Public Key Cryptosystem for generating keys. As a result, you can share your public key at `https://<your_api_address>/jwks`! 

**Peace of cake 🎂**

## Identity API (Who emits the token)

Install `NetDevPack.Security.Jwt.AspNetCore` in the API that issues JWT Tokens. Modify your Startup.cs:

```csharp
public void Configure(IApplicationBuilder app)
{
    app.UseJwksDiscovery().UseJwtValidation();
}
```
Generating the token:

```csharp
 private string EncodeToken(ClaimsIdentity identityClaims)
{
    var tokenHandler = new JwtSecurityTokenHandler();
    var currentIssuer = $"{ControllerContext.HttpContext.Request.Scheme}://{ControllerContext.HttpContext.Request.Host}";

    var key = _jwksService.GetCurrentSigningCredentials();
    var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
    {
        Issuer = currentIssuer,
        Subject = identityClaims,
        Expires = DateTime.UtcNow.AddHours(1),
        SigningCredentials = key
    });
    return tokenHandler.WriteToken(token);
}
```
## Client API

In your Client API, where JWT validation is required, install `NetDevPack.Security.JwtExtensions`. Next, update your `Startup.cs`:


```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddControllers();

    services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(x =>
    {
        x.RequireHttpsMetadata = true;
        x.SaveToken = true; // keep the public key at Cache for 10 min.
        x.IncludeErrorDetails = true; // <- great for debugging
        x.SetJwksOptions(new JwkOptions("https://localhost:5001/jwks"));
    });
}

public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{
    // ...
    app.UseAuthentication();
    app.UseAuthorization();
    // ...
}
```
At your `Controller`:

```csharp

[Authorize]
public class IdentityController : ControllerBase
{
    public IActionResult Get()
    {
        return new JsonResult(from c in User.Claims select new { c.Type, c.Value });
    }
}
```

Done 👌!

# 💾 Storage

By default, `NetDevPack.Security.Jwt` stores keys in the same location where ASP.NET Core stores its Cryptographic Key Material. It utilizes the [IXmlRepository](https://github.com/dotnet/aspnetcore/blob/d8906c8523f071371ce95d4e2d2fdfa89858047e/src/DataProtection/DataProtection/src/KeyManagement/XmlKeyManager.cs).

Any changes made to DataProtection will apply to this as well.

You can override the default behavior by adding another provider and customizing it according to your needs.

## Database

The `NetDevPack.Security.Jwt` package offers a method for storing your keys in a database using EntityFramework Core.

Install via NuGet Package Manager:
```
    Install-Package NetDevPack.Security.Jwt.Store.EntityFrameworkCore
``` 

Or through the .NET Core command line interface:

```
    dotnet add package NetDevPack.Security.Jwt.Store.EntityFrameworkCore
```

Add `ISecurityKeyContext` to your DbContext:

``` c#
class MyKeysContext : DbContext, ISecurityKeyContext
{
    public MyKeysContext(DbContextOptions<MyKeysContext> options) : base(options) { }

    // This maps to the table that stores keys.
    public DbSet<SecurityKeyWithPrivate> DataProtectionKeys { get; set; }
}
```

Then change your confinguration at `Startup.cs`
```csharp
public void ConfigureServices(IServiceCollection services)
{
    services.AddJwksManager().PersistKeysToDatabaseStore<MyKeysContext>();
}
```

Done! 

## File system

The `NetDevPack.Security.Jwt` package provides a mechanism for storing yor Keys to filesystem. 

Install
```
    Install-Package NetDevPack.Security.Jwt.Store.FileSystem
``` 

Or via the .NET Core command line interface:

```
    dotnet add package NetDevPack.Security.Jwt.Store.FileSystem
```

Now change your `startup.cs`

``` c#
public void ConfigureServices(IServiceCollection services)
{
    services.AddJwksManager().PersistKeysToFileSystem(new DirectoryInfo(@"c:\temp-keys\"));
}
```

# Samples

You can find several examples [here](samples/Server.AsymmetricKey)

# Changing Algorithm

It's possible to modify the default algorithm during the configuration process.

``` c#
build.Services.AddJwksManager(o =>
{
    o.Jws = Algorithm.Create(DigitalSignaturesAlgorithm.RsaSsaPssSha256);
    o.Jwe = Algorithm.Create(EncryptionAlgorithmKey.RsaOAEP).WithContentEncryption(EncryptionAlgorithmContent.Aes128CbcHmacSha256);
});
```
By default, it uses recommended algorithms according to [RFC7518](https://datatracker.ietf.org/doc/html/rfc7518)
```c#
build.Services.AddJwksManager(o =>
{
    o.Jws { get; set; } = Algorithm.Create(AlgorithmType.RSA, JwtType.Jws);
    o.Jwe { get; set; } = Algorithm.Create(AlgorithmType.RSA, JwtType.Jwe);
}
```
The Algorithm object offers a variety of options to choose from.

## Jws

Algorithms:

| Shortname | Name              |
| --------- | ----------------- |
| HS256     | Hmac Sha256       |
| HS384     | Hmac Sha384       |
| HS512     | Hmac Sha512       |
| RS256     | Rsa Sha256        |
| RS384     | Rsa Sha384        |
| RS512     | Rsa Sha512        |
| PS256     | Rsa SsaPss Sha256 |
| PS384     | Rsa SsaPss Sha384 |
| PS512     | Rsa SsaPss Sha512 |
| ES256     | Ecdsa Sha256      |
| ES384     | Ecdsa Sha384      |
| ES512     | Ecdsa Sha512      |

## Jwe

Algorithms options:

| Shortname | Key Management Algorithm |
| --------- | ------------------------ |
| RSA1_5    | RSA1_5                   |
| RsaOAEP   | RSAES OAEP using         |
| A128KW    | A128KW                   |
| A256KW    | A256KW                   |

Encryption options

| Shortname           | Content Encryption Algorithm |
| ------------------- | ---------------------------- |
| Aes128CbcHmacSha256 | A128CBC-HS256                |
| Aes192CbcHmacSha384 | A192CBC-HS384                |
| Aes256CbcHmacSha512 | A256CBC-HS512                |


# IdentityServer4 - Auto jwks_uri Management

`NetDevPack.Security.Jwt`  provides `IdentityServer4` key material. It auto generates and rotate key.


First install 
```
    Install-Package NetDevPack.Security.Jwt.IdentityServer4
``` 

Or via the .NET Core command line interface:

```
    dotnet add package NetDevPack.Security.Jwt.IdentityServer4
```

Go to Startup.cs

``` c#
    public void ConfigureServices(IServiceCollection services)
    {
        var builder = services.AddIdentityServer()
            .AddInMemoryIdentityResources(Config.GetIdentityResources())
            .AddInMemoryApiResources(Config.GetApis())
            .AddInMemoryClients(Config.GetClients());

        services.AddJwksManager().IdentityServer4AutoJwksManager();
    }
```

If you wanna use Database, follow instructions to DatabaseStore instead.

# Why

When developing applications and APIs using OAuth 2.0 or simply signing a JWT key, various algorithms are supported. Among these algorithms, some are considered best practices and superior to others, such as the Elliptic Curve with PS256 algorithm. Certain Auth servers operate with deterministic algorithms, while others use probabilistic ones. Some servers, like Auth0, do not support multiple JWKs, but IdentityServer4 supports as many as you configure. This component is designed to abstract this layer and offer your application the current best practices for JWK management.

## Load Balance scenarios

When working with containers in Kubernetes or Docker Swarm, scaling your applications can lead to certain issues, such as needing to store DataProtection keys in a centralized location. While it is not recommended to bypass this situation, using symmetric keys is one possible solution. Similar to DataProtection, this component provides a centralized store for your JWKS.

## Best practices

Many developers are unsure about which algorithm to use for signing their JWTs. By default, this component uses Elliptic Curve with ECDSA, utilizing P-256 and SHA-256 to help build more secure APIs and environments. It simplifies JWKS management by providing a better understanding of best practices and ensuring the use of secure algorithms.

---------------

# License

NetDevPack.Security.Jwt is Open Source software and is released under the MIT license. This license allow the use of NetDevPack.Security.Jwt in free and commercial applications and libraries without restrictions.
