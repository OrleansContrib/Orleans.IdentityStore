using Orleans.Runtime;

namespace Orleans.IdentityStore.Grains
{
    /// <summary>
    /// Get role ID by normalized role name
    /// </summary>
    public interface IIdentityRoleByNameGrain : IIdentityByStringGrain
    {
    }

    /// <summary>
    /// Gets userId by normalized email
    /// </summary>
    public interface IIdentityUserByEmailGrain : IIdentityByStringGrain
    {
    }

    /// <summary>
    /// Gets userId by login
    /// </summary>
    public interface IIdentityUserByLoginGrain : IIdentityByStringGrain
    {
    }

    /// <summary>
    /// Gets userId by normalized username
    /// </summary>
    public interface IIdentityUserByNameGrain : IIdentityByStringGrain
    {
    }

    internal class IdentityRoleByNameGrain : IdentityByStringGrain, IIdentityRoleByNameGrain
    {
        public IdentityRoleByNameGrain(
            [PersistentState("IdentityByString", OrleansIdentityConstants.OrleansStorageProvider)] IPersistentState<IdentityByStringState> data)
            : base(data)
        {
        }
    }

    internal class IdentityUserByEmailGrain : IdentityByStringGrain, IIdentityUserByEmailGrain
    {
        public IdentityUserByEmailGrain(
            [PersistentState("IdentityByString", OrleansIdentityConstants.OrleansStorageProvider)] IPersistentState<IdentityByStringState> data)
            : base(data)
        {
        }
    }

    internal class IdentityUserByLoginGrain : IdentityByStringGrain, IIdentityUserByLoginGrain
    {
        public IdentityUserByLoginGrain(
            [PersistentState("IdentityByString", OrleansIdentityConstants.OrleansStorageProvider)] IPersistentState<IdentityByStringState> data)
            : base(data)
        {
        }
    }

    internal class IdentityUserByNameGrain : IdentityByStringGrain, IIdentityUserByNameGrain
    {
        public IdentityUserByNameGrain(
            [PersistentState("IdentityByString", OrleansIdentityConstants.OrleansStorageProvider)] IPersistentState<IdentityByStringState> data)
            : base(data)
        {
        }
    }
}