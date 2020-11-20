using Orleans;
using Orleans.Concurrency;
using Orleans.Runtime;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Orleans.IdentityStore.Grains
{
    internal interface ILookupGrain : IGrainWithStringKey
    {
        Task<bool> AddOrUpdate(string value, Guid grainKey);

        Task Delete(string value);

        Task DeleteIfMatch(string value, Guid grainKey);

        [AlwaysInterleave]
        Task<Guid?> Find(string value);

        [AlwaysInterleave]
        Task<IReadOnlyDictionary<string, Guid>> GetAll();
    }

    internal class LookupGrain : Grain, ILookupGrain
    {
        private readonly IPersistentState<LookupGrainState> _index;

        public LookupGrain(
            [PersistentState(nameof(LookupGrainState), OrleansIdentityConstants.OrleansStorageProvider)] IPersistentState<LookupGrainState> index)
        {
            _index = index;
        }

        public async Task<bool> AddOrUpdate(string value, Guid grainKey)
        {
            if (_index.State.Index.ContainsKey(value))
                return false;

            _index.State.Index[value] = grainKey;
            await _index.WriteStateAsync();
            return true;
        }

        public Task Delete(string value)
        {
            if (_index.State.Index.Remove(value))
                return _index.WriteStateAsync();

            return Task.CompletedTask;
        }

        public Task DeleteIfMatch(string value, Guid grainKey)
        {
            if (_index.State.Index.ContainsKey(value) && _index.State.Index[value] == grainKey)
            {
                _index.State.Index.Remove(value);
                return _index.WriteStateAsync();
            }
            return Task.CompletedTask;
        }

        public Task<Guid?> Find(string value)
        {
            if (_index.State.Index.ContainsKey(value))
                return Task.FromResult<Guid?>(_index.State.Index[value]);

            return Task.FromResult<Guid?>(default);
        }

        public Task<IReadOnlyDictionary<string, Guid>> GetAll()
        {
            return Task.FromResult<IReadOnlyDictionary<string, Guid>>(_index.State.Index);
        }
    }

    internal class LookupGrainState
    {
        public Dictionary<string, Guid> Index { get; set; } = new Dictionary<string, Guid>();
    }
}