namespace Orleans.IdentityStore
{
    /// <summary>
    /// Constants used by library
    /// </summary>
    public static class OrleansIdentityConstants
    {
        /// <summary>
        /// The grains persistences name
        /// </summary>
        public const string OrleansStorageProvider = "OrleansIdentityStore";

        /// <summary>
        /// The username lookup name
        /// </summary>
        public const string UsernameLookup = "__username";

        /// <summary>
        /// The email lookup name
        /// </summary>
        public const string EmailLookup = "__email";

        /// <summary>
        /// The role name lookup
        /// </summary>
        public const string RoleLookup = "__role";
    }
}