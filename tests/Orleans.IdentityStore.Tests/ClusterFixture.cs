using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Hosting;
using Orleans.Hosting;
using Orleans.TestingHost;
using System;
using Xunit;

namespace Orleans.IdentityStore.Tests
{
    [CollectionDefinition(Name)]
    public class ClusterCollection : ICollectionFixture<ClusterFixture>
    {
        public const string Name = "ClusterCollection";
    }

    public class ClusterFixture : IDisposable
    {
        public ClusterFixture()
        {
            var builder = new TestClusterBuilder();
            builder.AddSiloBuilderConfigurator<TestSiloConfigurations>();

            Cluster = builder.Build();
            Cluster.Deploy();
        }

        public TestCluster Cluster { get; }

        public void Dispose()
        {
            this.Cluster.StopAllSilos();
        }

        public class TestSiloConfigurations : ISiloConfigurator, IHostConfigurator
        {
            public void Configure(ISiloBuilder siloBuilder)
            {
                siloBuilder
                    .ConfigureApplicationParts(parts => parts.AddApplicationPart(typeof(IdentityUser<Guid>).Assembly).WithReferences())
                    .UseOrleanIdentityStore();
            }

            public void Configure(IHostBuilder hostBuilder)
            {
            }
        }
    }

    [CollectionDefinition("ClusterCollection")]
    public class DummyCollection : ICollectionFixture<string>
    {
    }
}