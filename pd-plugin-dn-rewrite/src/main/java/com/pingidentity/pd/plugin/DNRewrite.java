package com.pingidentity.pd.plugin;

import com.unboundid.directory.sdk.common.operation.SimpleBindRequest;
import com.unboundid.directory.sdk.common.operation.UpdatableBindResult;
import com.unboundid.directory.sdk.common.operation.UpdatableSimpleBindRequest;
import com.unboundid.directory.sdk.common.types.ActiveOperationContext;
import com.unboundid.directory.sdk.ds.api.Plugin;
import com.unboundid.directory.sdk.ds.config.PluginConfig;
import com.unboundid.directory.sdk.ds.types.DirectoryServerContext;
import com.unboundid.directory.sdk.ds.types.PostOperationPluginResult;
import com.unboundid.directory.sdk.ds.types.PreParsePluginResult;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.LDAPResult;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.StringArgument;

import java.util.List;

/**
 * This simple plugin extension rewrites the DN of incoming requests.
 */
public class DNRewrite extends Plugin {

    public static final String ARG_NAME_PREFIX = "prefix";
    private String prefix;
    private DirectoryServerContext serverContext;

    @Override
    public String getExtensionName() {
        return "pd-plugin-dn-rewrite";
    }

    @Override
    public String[] getExtensionDescription() {
        return new String[]{"This simple plugin extension rewrites the DN of incoming requests."};
    }

    @Override
    public void defineConfigArguments(ArgumentParser parser) throws ArgumentException {
        parser.addArgument(new DNArgument(null, ARG_NAME_PREFIX, true, 1,
                "{prefix}", "DN prefix to add to the DN of incoming requests"));
    }

    @Override
    public ResultCode applyConfiguration(PluginConfig config, ArgumentParser parser, List<String> adminActionsRequired, List<String> messages) {
        String p=parser.getDNArgument(ARG_NAME_PREFIX).getStringValue();
        if (!p.endsWith(",")){
            p+=",";
        }
        this.prefix=p;
        return ResultCode.SUCCESS;
    }

    @Override
    public void initializePlugin(DirectoryServerContext serverContext, PluginConfig config, ArgumentParser parser) throws LDAPException {
        this.serverContext=serverContext;
        applyConfiguration(config,parser,null,null);
    }

    /**
     * This method performs the necessary processing to inject the DN prefix when an incoming Simple BIND request
     * is processed, before it is fully parsed.
     * @param operationContext the operation context
     * @param request the request to examine
     * @param result the result of the request (useful in case where processing should be interrupted
     *              at this stage and a result be immediately returned to the client)
     * @return the result of the examination itself. This controls whether normal server processing continues.
     */
    @Override
    public PreParsePluginResult doPreParse(ActiveOperationContext operationContext, UpdatableSimpleBindRequest request, UpdatableBindResult result) {
        request.setDN(prefix+request.getDN());
        return PreParsePluginResult.SUCCESS;
    }

    /**
     * Performs the necessary processing to remove the DN prefix before returning the result to the client
     * @param operationContext the operation context
     * @param request the request received
     * @param result the result of the request
     * @return the result of the post operation processing
     */
    @Override
    public PostOperationPluginResult doPostOperation(ActiveOperationContext operationContext, SimpleBindRequest request, UpdatableBindResult result) {
        if ( result.getMatchedDN().startsWith(prefix) ){
            LDAPResult r = result.toLDAPSDKResult();
            result.setResultData(new LDAPResult(r.getMessageID(), r.getResultCode(), r.getDiagnosticMessage(), r.getMatchedDN().replaceFirst(prefix,""),r.getReferralURLs(),r.getResponseControls()));
        }
        return PostOperationPluginResult.SUCCESS;
    }
}