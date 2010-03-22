﻿using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Xml.Serialization;
using DotNetCasClient.Validation.Schema.Saml11.Assertion;

namespace DotNetCasClient.Validation.Schema.Saml11.Protocol.SubjectQuery
{
    [XmlInclude(typeof(AuthorizationDecisionQueryType))]
    [XmlInclude(typeof(AttributeQueryType))]
    [XmlInclude(typeof(AuthenticationQueryType))]
    [Serializable]
    [DebuggerStepThrough]
    [DesignerCategory("code")]
    [XmlType(Namespace="urn:oasis:names:tc:SAML:1.0:protocol")]
    [XmlRoot("SubjectQuery", Namespace="urn:oasis:names:tc:SAML:1.0:protocol", IsNullable=false)]
    public abstract class SubjectQueryAbstractType : QueryAbstractType {
        [XmlElement(Namespace="urn:oasis:names:tc:SAML:1.0:assertion")]
        public SubjectType Subject
        {
            get;
            set;
        }
    }
}