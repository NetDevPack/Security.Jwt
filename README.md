
# ASP.NET Core RESTFul Extensions
![Nuget](https://img.shields.io/nuget/v/AspNetCore.RESTFul.Extensions)![Azure DevOps coverage](https://img.shields.io/azure-devops/coverage/brunohbrito/AspNet.Core.RESTFul.Extensions/14)[![Build Status](https://dev.azure.com/brunohbrito/AspNet.Core.RESTFul.Extensions/_apis/build/status/brunohbrito.AspNet.Core.RESTFul.Extensions?branchName=master)](https://dev.azure.com/brunohbrito/AspNet.Core.RESTFul.Extensions/_build/latest?definitionId=14&branchName=master)

<img align="right" width="100px" src="https://jpproject.blob.core.windows.net/images/restful-icon-github.png" />
Lightweight API that construct custom IQueryable LINQ Extensions to help you filter, sort and paginate your objects from a custom Class and expose it as GET parameter.


## Table of Contents ##

- [ASP.NET Core RESTFul Extensions](#aspnet-core-restful-extensions)
  - [Table of Contents](#table-of-contents)
- [How](#how)
- [Sort](#sort)
- [Paging](#paging)
- [All in One](#all-in-one)
- [Criterias for filtering](#criterias-for-filtering)
- [Different database fields name](#different-database-fields-name)
- [Why](#why)
- [License](#license)

------------------

# How #

Create a class with filtering properties:

``` c#
public class UserSearch
{
    public string Username { get; set; }

    [Rest(Operator = WhereOperator.GreaterThan)]
    public DateTime? Birthday { get; set; }

    [Rest(Operator = WhereOperator.Contains, HasName = "Firstname")]
    public string Name { get; set; }
}
```

Expose this class as GET in your API and use it to Filter your collection:

``` c#
[HttpGet("")]
public async Task<ActionResult<IEnumerable<User>>> Get([FromQuery] UserSearch search)
{
    var result = await context.Users.AsQueryable().Filter(search).ToListAsync();

    return Ok(result);
}
```

Done! 
<img align="right" width="100px" src="https://jpproject.blob.core.windows.net/images/restful-icon.png" />
You can send a request to you API like this: `https://www.myapi.com/users?username=bhdebrito@gmail.com&name=bruno`


The component will construct a IQueryable. If you are using an ORM like EF Core it construct a SQL query based in IQueryable, improving performance.

# Sort

A comma separetd fields. E.g username,birthday,-firstname

**-**(minus) for **descending** **+**(plus) or nothing for **ascending**

``` c#
public class UserSearch
{
    public string Username { get; set; }

    public string SortBy { get; set; }
}
```


``` c#
[HttpGet("")]
public async Task<ActionResult<IEnumerable<User>>> Get([FromQuery] UserSearch search)
{
    var result = await context.Users.AsQueryable().Filter(search).Sort(search.SortBy).ToListAsync();

    return Ok(result);
}
```
Example GET: `https://www.myapi.com/users?username=bruno&sortby=username,-birtday`
<img align="right" width="100px" src="https://jpproject.blob.core.windows.net/images/restful-icon-2.png" />

# Paging

A exclusive extension for paging


``` c#
public class UserSearch
{
    public string Username { get; set; }

    [Rest(Max = 100)]
    public int Limit { get; set; } = 10;

    public int Offset { get; set; } = 0;
}
```

**Limit** is the total results in response. **Offset** is how many rows to Skip. Optionally you can set the `Max` attribute to restrict the max items of pagination.

``` c#
[HttpGet("")]
public async Task<ActionResult<IEnumerable<User>>> Get([FromQuery] UserSearch search)
{
    var result = await context.Users.AsQueryable().Filter(search).Paging(search.Limit, search.Offset).ToListAsync();

    return Ok(result);
}
```

Example GET: `https://www.myapi.com/users?username=bruno&limit=10&offset=20`
<img align="right" width="100px" src="https://jpproject.blob.core.windows.net/images/all-in-one.png" />

# All in One


Create a search class like this

``` c#
public class UserSearch : IRestSort, IRestPagination
{
    public string Username { get; set; }

    [Rest(Operator = WhereOperator.GreaterThan)]
    public DateTime? Birthday { get; set; }

    [Rest(Operator = WhereOperator.Contains, HasName = "Firstname")]
    public string Name { get; set; }

    public int Offset { get; set; }
    public int Limit { get; set; } = 10;
    public string Sort { get; set; }
}
```
Call Apply method, instead calling each one with custom parameters.

``` c#
[HttpGet("")]
public async Task<ActionResult<IEnumerable<User>>> Get([FromQuery] UserSearch search)
{
    var result = await context.Users.AsQueryable().Apply(search).ToListAsync();

    return Ok(result);
}
```

`IRestSort` and `IRestPagination` give the ability for method `Apply` use **Sort** and **Pagination**. If don't wanna sort, just use pagination remove `IRestSort` Interface from Class.

# Criterias for filtering

When creating a Search class, you can define criterias by decorating your properties:

``` c#
public class CustomUserSearch
{
    [Rest(Operator = WhereOperator.Equals, UseNot = true)]
    public string Category { get; set; }

    [Rest(Operator = WhereOperator.GreaterThanOrEqualTo)]
    public int OlderThan { get; set; }

    [Rest(Operator = WhereOperator.StartsWith, CaseSensitive = true)]
    public string Username { get; set; }

    [Rest(Operator = WhereOperator.GreaterThan)]
    public DateTime? Birthday { get; set; }

    [Rest(Operator = WhereOperator.Contains)]
    public string Name { get; set; }
}
```

# Different database fields name

You can specify different property name to hide you properties original fields

``` c#
public class CustomUserSearch
{
    [Rest(Operator = WhereOperator.Equals, UseNot = true, HasName = "Privilege")]
    public string Category { get; set; }

    [Rest(Operator = WhereOperator.GreaterThanOrEqualTo)]
    public int OlderThan { get; set; }

    [Rest(Operator = WhereOperator.StartsWith, CaseSensitive = true, HasName = "Username")]
    public string Email { get; set; }
}
```

# Why

RESTFul api's are hard to create. See the example get:

`https://www.myapi.com/users?name=bruno&age_lessthan=30&sortby=name,-age&limit=20&offset=20`

How many code you need to perform such search? A custom filter for each Field, maybe a for and a switch for each `sortby` and after all apply pagination.
How many resources your api have? 

This lightweight API create a custom IQueryable based in Querystring to help your ORM or LINQ to filter data.

---------------

# License

AspNet.Core.RESTFul.Extensions is Open Source software and is released under the MIT license. This license allow the use of AspNet.Core.RESTFul.Extensions in free and commercial applications and libraries without restrictions.

