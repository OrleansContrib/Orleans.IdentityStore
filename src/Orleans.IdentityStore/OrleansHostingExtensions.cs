using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Orleans.IdentityStore;
using Orleans.IdentityStore.Grains;

namespace Orleans.Hosting
{
    /// <summary>
    /// Silo hosting extensions
    /// </summary>
    public static class SiloBuilderExtensions
    {
        /// <summary>
        /// Add identity store to orleans. Grain storage provider name can be found at <see
        /// cref="OrleansIdentityConstants.OrleansStorageProvider"/> ///
        /// </summary>
        /// <param name="builder">Silo builder</param>
        public static ISiloBuilder UseOrleanIdentityStore(this ISiloBuilder builder)
        {
            builder.ConfigureServices(s => s.AddSingleton<ILookupNormalizer, UpperInvariantLookupNormalizer>());
            try
            {
                builder.AddMemoryGrainStorage(OrleansIdentityConstants.OrleansStorageProvider);
            }
            catch
            {
                // Store was already added
            }

            //JsonConvert.DefaultSettings = () =>
            //{
            //    return new JsonSerializerSettings()
            //    {
            //        Converters = new List<JsonConverter>() { new JsonClaimConverter(), new JsonClaimsPrincipalConverter(), new JsonClaimsIdentityConverter() }
            //    };
            //};

            return builder
                .ConfigureApplicationParts(parts => parts.AddApplicationPart(typeof(ILookupGrain).Assembly).WithReferences());
        }

        /// <summary>
        /// Add identity store to orleans. Grain storage provider name can be found at <see
        /// cref="OrleansIdentityConstants.OrleansStorageProvider"/> ///
        /// </summary>
        /// <param name="builder">Silo builder</param>
        public static ISiloHostBuilder UseOrleanIdentityStore(this ISiloHostBuilder builder)
        {
            builder.ConfigureServices(s => s.AddSingleton<ILookupNormalizer, UpperInvariantLookupNormalizer>());
            try
            {
                builder.AddMemoryGrainStorage(OrleansIdentityConstants.OrleansStorageProvider);
            }
            catch
            {
                // Store was already added
            }

            //JsonConvert.DefaultSettings = () =>
            //{
            //    return new JsonSerializerSettings()
            //    {
            //        Converters = new List<JsonConverter>() { new JsonClaimConverter(), new JsonClaimsPrincipalConverter(), new JsonClaimsIdentityConverter() }
            //    };
            //};

            return builder
                .ConfigureApplicationParts(parts => parts.AddApplicationPart(typeof(ILookupGrain).Assembly).WithReferences());
        }
    }
}