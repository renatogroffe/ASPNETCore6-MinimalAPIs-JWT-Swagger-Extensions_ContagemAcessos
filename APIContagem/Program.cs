using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using APIs.Security.JWT;
using APIContagem;
using APIContagem.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers().AddJsonOptions(options =>
{
    options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
});

builder.Services.AddEndpointsApiExplorer();

// Configurando o uso do Swagger para prever tokens JWT
builder.Services.AddSwaggerGenJwt("v1",
    new OpenApiInfo
    {
        Title = "APIContagem",
        Description = "Exemplo de implementação de uso de JWT com Minimal APIs - Contagem de acessos",
        Version = "v1",
        Contact = new OpenApiContact()
        {
            Name = "Renato Groffe",
            Url = new Uri("https://github.com/renatogroffe"),
        },
        License = new OpenApiLicense()
        {
            Name = "MIT",
            Url = new Uri("http://opensource.org/licenses/MIT"),
        }
    });

// Configurando o uso da classe de contexto para
// acesso às tabelas do ASP.NET Identity Core
builder.Services.AddDbContext<ApiSecurityDbContext>(options =>
    options.UseInMemoryDatabase("InMemoryDatabase"));

var tokenConfigurations = new TokenConfigurations();
new ConfigureFromConfigurationOptions<TokenConfigurations>(
    builder.Configuration.GetSection("TokenConfigurations"))
        .Configure(tokenConfigurations);

// Aciona a extensão que irá configurar o uso de
// autenticação e autorização via tokens
builder.Services.AddJwtSecurity(tokenConfigurations);

// Acionar caso seja necessário criar usuários para testes
builder.Services.AddScoped<IdentityInitializer>();

builder.Services.AddSingleton<Contador>();

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "APIContagem v1");
});

// Criação de estruturas, usuários e permissões
// na base do ASP.NET Identity Core (caso ainda não
// existam)
using var scope = app.Services.CreateScope();
scope.ServiceProvider.GetRequiredService<IdentityInitializer>().Initialize();

app.UseAuthorization();

app.MapGet("/contador", [Authorize("Bearer")] (Contador contador) =>
{
    int valorAtualContador;
    lock (contador)
    {
        contador.Incrementar();
        valorAtualContador = contador.ValorAtual;
    }
    app.Logger.LogInformation($"Contador - Valor atual: {valorAtualContador}");    

    return new ResultadoContador()
    {
        ValorAtual = contador.ValorAtual,
        Local = contador.Local,
        Kernel = contador.Kernel,
        Saudacao = app.Configuration["Saudacao"],
        Framework = contador.Framework
    };
}).Produces<ResultadoContador>()
  .Produces(StatusCodes.Status401Unauthorized);

app.MapPost("/login", [AllowAnonymous] (User usuario, AccessManager accessManager) =>
{
    app.Logger.LogInformation($"Recebida solicitação para o usuário: {usuario?.UserID}");
    if (usuario is not null && accessManager.ValidateCredentials(usuario))
    {
        app.Logger.LogInformation($"Sucesso na autenticação do usuário: {usuario!.UserID}");
        return Results.Ok(accessManager.GenerateToken(usuario));
    }
    else
    {
        app.Logger.LogError($"Falha na autenticação do usuário: {usuario?.UserID}");
        return Results.Unauthorized();
    }
}).Produces<Token>()
  .Produces(StatusCodes.Status401Unauthorized);

app.Run();