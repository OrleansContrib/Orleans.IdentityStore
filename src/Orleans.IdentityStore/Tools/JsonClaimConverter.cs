using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Security.Claims;

namespace Orleans.IdentityStore.Tools
{
    internal class JsonClaimConverter : JsonConverter
    {
        public override bool CanConvert(Type objectType)
        {
            return objectType == typeof(Claim);
        }

        public override object ReadJson(JsonReader reader, Type objectType, object existingValue, JsonSerializer serializer)
        {
            var jo = JObject.Load(reader);
            string type = (string)jo["Type"];
            var token = jo["Value"];
            string value = token.Type == JTokenType.String ? (string)token : token.ToString(Formatting.None);
            string valueType = (string)jo["ValueType"];
            string issuer = (string)jo["Issuer"];
            string originalIssuer = (string)jo["OriginalIssuer"];
            return new Claim(type, value, valueType, issuer, originalIssuer);
        }

        public override void WriteJson(JsonWriter writer, object value, JsonSerializer serializer)
        {
            var claim = (Claim)value;
            var jo = new JObject();
            jo.Add("Type", claim.Type);
            jo.Add("Value", claim.Value);
            jo.Add("ValueType", claim.ValueType);
            jo.Add("Issuer", claim.Issuer);
            jo.Add("OriginalIssuer", claim.OriginalIssuer);
            jo.WriteTo(writer);
        }
    }
}