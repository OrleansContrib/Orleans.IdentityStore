using Orleans.IdentityStore.Grains;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;

namespace Orleans.IdentityStore
{
    internal static class GrainFactoryIndexingExtensions
    {
        /// <summary>
        /// This is the number of buckets.  If you change this number, it will break existing deployments
        /// </summary>
        private const int BucketCount = 2459;

        public static Task<bool> AddOrUpdateToLookup(this IGrainFactory factory, string lookupName, string value, Guid grainKey)
        {
            return factory.GetGrain<ILookupGrain>($"{lookupName}/{GetBucket(value)}").AddOrUpdate(value, grainKey);
        }

        public static Task RemoveFromLookup(this IGrainFactory factory, string lookupName, string value)
        {
            return factory.GetGrain<ILookupGrain>($"{lookupName}/{GetBucket(value)}").Delete(value);
        }

        public static Task SafeRemoveFromLookup(this IGrainFactory factory, string lookupName, string value, Guid grainKey)
        {
            return factory.GetGrain<ILookupGrain>($"{lookupName}/{GetBucket(value)}").DeleteIfMatch(value, grainKey);
        }

        public static async Task<TGrain> Find<TGrain>(this IGrainFactory factory, string lookupName, string value) where TGrain : IGrain
        {
            var result = await factory.GetGrain<ILookupGrain>($"{lookupName}/{GetBucket(value)}").Find(value);

            if (result != null)
            {
                return (TGrain)factory.GetGrain(typeof(TGrain), result.Value);
            }

            return default;
        }

        public static async IAsyncEnumerable<TGrain> Search<TGrain>(this IGrainFactory factory, string lookupName, Func<string, bool> func) where TGrain : IGrain
        {
            for (var i = 0; i < BucketCount; i++)
            {
                var bucket = await factory.GetGrain<ILookupGrain>($"{lookupName}/{i}").GetAll();
                if (bucket != null)
                {
                    foreach (var e in bucket)
                    {
                        if (func(e.Key))
                        {
                            yield return (TGrain)factory.GetGrain(typeof(TGrain), e.Value);
                        }
                    }
                }
            }
        }

        internal static int GetBucket(string text)
        {
            unchecked
            {
                int hash = 113647;
                foreach (char c in text)
                {
                    hash = (hash * 31) + c;
                }

                return hash & BucketCount;
            }
        }
    }
}