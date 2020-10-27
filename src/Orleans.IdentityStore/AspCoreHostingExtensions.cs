using Microsoft.AspNetCore.Identity;
using Orleans.IdentityStore.Stores;
using System;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Hosting extensions
    /// </summary>
    public static class AspCoreHostingExtensions
    {
        /// <summary>
        /// Use orleans as your user store
        /// </summary>
        /// <param name="builder">Identity builder</param>
        public static IdentityBuilder AddOrleansStores(this IdentityBuilder builder)
        {
            //JsonConvert.DefaultSettings = () =>
            //{
            //    return new JsonSerializerSettings()
            //    {
            //        Converters = new List<JsonConverter>() { new JsonClaimConverter(), new JsonClaimsPrincipalConverter(), new JsonClaimsIdentityConverter() }
            //    };
            //};

            var roleType = builder.RoleType ?? typeof(IdentityRole<Guid>);

            builder.Services.AddTransient(
                    typeof(IRoleClaimStore<>).MakeGenericType(roleType),
                    typeof(OrleansRoleStore<,>).MakeGenericType(builder.UserType, roleType));

            builder.Services.AddTransient(
            typeof(IUserStore<>).MakeGenericType(builder.UserType),
            typeof(OrleansUserStore<,>).MakeGenericType(builder.UserType, roleType));

            builder.Services.AddSingleton<ILookupNormalizer, UpperInvariantLookupNormalizer>();
            return builder;
        }
    }
}