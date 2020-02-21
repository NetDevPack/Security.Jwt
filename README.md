# Json Web Key Set Manager
![Nuget](https://img.shields.io/nuget/v/Jwks.Manager)![Azure DevOps coverage](https://img.shields.io/azure-devops/coverage/brunohbrito/Jwks.Manager/14)[![Build Status](https://dev.azure.com/brunohbrito/Jwks.Manager/_apis/build/status/brunohbrito.Jwks.Manager?branchName=master)](https://dev.azure.com/brunohbrito/Jwks.Manager/_build/latest?definitionId=15&branchName=master)

<img align="right" width="100px" src="https://jpproject.blob.core.windows.net/images/helldog-site.png" />
The JSON Web Key Set (JWKS) is a set of keys which contains the public keys used to verify any JSON Web Token (JWT) issued by the authorization server. 
The main goal of this component is to provide a centralized store and Key Rotation of your JWK. It also provide features to generate best practices JWK.
It has a plugin for IdentityServer4, giving hability to rotating jwks_uri every 90 days and auto manage your jwks_uri.

If your API or OAuth 2.0 is under Load Balance in Kubernetes, or docker swarm it's a must have component. It work in the same way DataProtection Key of ASP.NET Core.

## Table of Contents ##

- [Json Web Key Set Manager](#json-web-key-set-manager)
  - [Table of Contents](#table-of-contents)
- [How](#how)
  - [Database](#database)
  - [File system](#file-system)
- [Changing Algorithm](#changing-algorithm)
- [IdentityServer4 - Auto jwks_uri Management](#identityserver4---auto-jwksuri-management)
- [Signing JWT](#signing-jwt)
  - [Token Validation](#token-validation)
- [Why](#why)
  - [Load Balance scenarios](#load-balance-scenarios)
  - [Best practices](#best-practices)
- [License](#license)

------------------

# How #

First choose where to store your JWK's.


## Database

The [Jwks.Manager.EntityFrameworkCore](https://www.nuget.org/packages/Jwks.Manager.EntityFrameworkCore) package provides a mechanism for storing JsonWebKeys to a database using Entity Framework Core. `The Jwks.Manager.EntityFrameworkCore` NuGet package must be added to the project file.

With this package, keys can be shared across multiple instances of a web app.

First install 
```
    Install-Package Jwks.Manager.EntityFrameworkCore
``` 

Or via the .NET Core command line interface:

```
    dotnet add package Jwks.Manager.EntityFrameworkCore
```

Change your Startup.cs

``` c#
public void ConfigureServices(IServiceCollection services)
{
    services.AddDbContext<ApplicationDbContext>(options =>
        options.UseSqlServer(
            Configuration.GetConnectionString("DefaultConnection")));

    // Add a DbContext to store your Database Keys
    services.AddDbContext<MyKeysContext>(options =>
        options.UseSqlServer(
            Configuration.GetConnectionString("MyKeysConnection")));

    // using Jwks.Manager.EntityFrameworkCore;
    services.AddJwksManager().PersistKeysToDatabaseStore<MyKeysContext>();

}
```
The generic parameter, TContext, must inherit from DbContext and implement `ISecurityKeyContext`:

``` c#
using Jwks.Manager.Store.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using WebApp1.Data;

namespace WebApp1
{
    class MyKeysContext : DbContext, ISecurityKeyContext
    {
        // A recommended constructor overload when using EF Core 
        // with dependency injection.
        public MyKeysContext(DbContextOptions<MyKeysContext> options) 
            : base(options) { }

        // This maps to the table that stores keys.
        public DbSet<SecurityKeyWithPrivate> DataProtectionKeys { get; set; }
    }
}
```

Done! 


## File system

To configure a file system-based key repository, call the PersistKeysToFileSystem configuration routine as shown below. Provide a DirectoryInfo pointing to the repository where keys should be stored:

``` c#
public void ConfigureServices(IServiceCollection services)
{
    services.AddJwksManager().PersistKeysToFileSystem(new DirectoryInfo(@"c:\temp-keys\"));
}
```

# Changing Algorithm

It's possible to change default Algorithm at configuration routine.

``` c#
public void ConfigureServices(IServiceCollection services)
{
    services.AddJwksManager(o => o.Algorithm = Algorithm.RS384).PersistKeysToFileSystem(new DirectoryInfo(@"c:\temp-keys\"));
}
```

The Algorithm object has a list of possibilities:

|Shortname|Name|
|---------|-----|
|HS256| Hmac Sha256|
|HS384| Hmac Sha384|
|HS512| Hmac Sha512|
|RS256| Rsa Sha256|
|RS384| Rsa Sha384|
|RS512| Rsa Sha512|
|PS256| Rsa SsaPss Sha256|
|PS384| Rsa SsaPss Sha384|
|PS512| Rsa SsaPss Sha512|
|ES256| Ecdsa Sha256|
|ES384| Ecdsa Sha384|
|ES512| Ecdsa Sha512|

# IdentityServer4 - Auto jwks_uri Management

If you have an IdentityServer4 OAuth 2.0 Server, you can use this component plugin.


First install 
```
    Install-Package Jwks.Manager.IdentityServer4
``` 

Or via the .NET Core command line interface:

```
    dotnet add package Jwks.Manager.IdentityServer4
```

Go to Startup.cs

``` c#
    public void ConfigureServices(IServiceCollection services)
    {
        var builder = services.AddIdentityServer()
            .AddInMemoryIdentityResources(Config.GetIdentityResources())
            .AddInMemoryApiResources(Config.GetApis())
            .AddInMemoryClients(Config.GetClients());

        services.AddJwksManager().IdentityServer4AutoJwksManager().PersistKeysToFileSystem(new DirectoryInfo(_env.WebRootPath));
    }
```

If you wanna use Database, follow instructions to DatabaseStore instead.

# Signing JWT

To signing a JWT Token do as follow.

First inject:

``` c#
    public class AccessManager
    {
        private readonly IJsonWebKeySetService _jwksService;

        public AccessManager(IJsonWebKeySetService jwksService)
        {
            _jwksService = jwksService;
        }
    }
```

Then, after a successfull login, create a routine to generate token.

``` c#
    public Token GenerateToken(User user)
    {
        ClaimsIdentity identity = new ClaimsIdentity(
            new GenericIdentity(user.UserID, "Login"),
            new[] {
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString("N")),
                new Claim(JwtRegisteredClaimNames.UniqueName, user.UserID)
            }
        );

        var now = DateTime.Now;

        var handler = new JsonWebTokenHandler();
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = "me",
            Audience = "you",
            SigningCredentials = _jwksService.GetCurrent(),
            Subject = identity,
            NotBefore = now,
            Expires = now.AddHours(1)
        };

        var jwt = handler.CreateToken(descriptor);

        return new Token()
        {
            Authenticated = true,
            Created = now.ToString("yyyy-MM-dd HH:mm:ss"),
            Expiration = now.AddHours(1).ToString("yyyy-MM-dd HH:mm:ss"),
            AccessToken = jwt,
            Message = "OK"
        };
    }
```

## Token Validation

To validate a token it's as simple as that:

``` c#
    var result = handler.ValidateToken(jwt,
            new TokenValidationParameters
            {
                ValidIssuer = "me",
                ValidAudience = "you",
                IssuerSigningKey = _jwksService.GetCurrent(options).Key
            });
```


# Why

When creating applications and APIs in OAuth 2.0 or simpling Signing a JWT Key, many algorithms are supported. While there a subset of alg's, some of them are considered best practices, and better than others. Like Elliptic Curve with PS256 algorithm. Some Auth Servers works with Deterministic and other with Probabilist. Some servers like Auth0 doesn't support more than one JWK. But IdentityServer4 support as many as you configure. So this component came to abstract this layer and offer for your application the current best practies for JWK.

## Load Balance scenarios

When working in containers with Kubernetes or Docker Swarm, if your application scale them you became to have some problems, like DataProtection Keys that must be stored in a centralized place. While isn't recommended to avoid this situation Symmetric Key is a way. So this component, like DataProtection, provide a Centralized store for your JWKS.

## Best practices

Many developers has no clue about which Algorithm to use for sign their JWT. This component uses Elliptic Curve with ECDSA using P-256 and SHA-256 as default. It should help to build more secure API's and environments providing JWKS management.


---------------

# License

Jwks.Manager is Open Source software and is released under the MIT license. This license allow the use of Jwks.Manager in free and commercial applications and libraries without restrictions.

