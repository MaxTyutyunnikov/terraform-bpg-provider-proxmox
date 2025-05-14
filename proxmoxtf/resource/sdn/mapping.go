package sdn

import (
	"github.com/bpg/terraform-provider-proxmox/proxmox/firewall"
	"github.com/bpg/terraform-provider-proxmox/proxmoxtf/structure"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

package resource

import (
"context"
"encoding/base64"
"errors"
"fmt"
"regexp"
"sort"
"strconv"
"strings"
"time"

"github.com/google/go-cmp/cmp"
"github.com/google/uuid"
"github.com/hashicorp/terraform-plugin-log/tflog"
"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
"github.com/hashicorp/terraform-plugin-sdk/v2/helper/customdiff"
"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

"github.com/bpg/terraform-provider-proxmox/proxmox/api"
"github.com/bpg/terraform-provider-proxmox/proxmox/cluster"
"github.com/bpg/terraform-provider-proxmox/proxmox/helpers/ptr"
"github.com/bpg/terraform-provider-proxmox/proxmox/nodes/vms"
"github.com/bpg/terraform-provider-proxmox/proxmox/pools"
"github.com/bpg/terraform-provider-proxmox/proxmox/types"
"github.com/bpg/terraform-provider-proxmox/proxmoxtf"
"github.com/bpg/terraform-provider-proxmox/proxmoxtf/resource/validators"
"github.com/bpg/terraform-provider-proxmox/proxmoxtf/resource/vm/disk"
"github.com/bpg/terraform-provider-proxmox/proxmoxtf/resource/vm/network"
"github.com/bpg/terraform-provider-proxmox/proxmoxtf/structure"
"github.com/bpg/terraform-provider-proxmox/utils"
)

const (
	mkMappingIP    = "ip"
	mkMappingMAC   = "mac"
)

func Mapping() *schema.Resource {
	s := map[string]*schema.Schema{
		mkMappingIP: {
			Type:        schema.TypeString,
			Description: "IP",
			Required:    true,
		},
		mkMappingMAC: {
			Type:        schema.TypeString,
			Description: "MAC",
			Required:    true,
		},
	}

	structure.MergeSchema(s, selectorSchema())

	return &schema.Resource{
		Schema:        s,
		CreateContext: selectMappingAPI(mappingCreate),
		ReadContext:   selectMappingAPI(mappingRead),
		UpdateContext: selectMappingAPI(mappingUpdate),
		DeleteContext: selectMappingAPI(mappingDelete),
	}
}

func mappingCreate(ctx context.Context, api firewall.API, d *schema.ResourceData) diag.Diagnostics {
	comment := d.Get(mkAliasComment).(string)
	name := d.Get(mkAliasName).(string)
	cidr := d.Get(mkAliasCIDR).(string)

	body := &firewall.AliasCreateRequestBody{
		Comment: &comment,
		Name:    name,
		CIDR:    cidr,
	}

	err := api.CreateAlias(ctx, body)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(name)

	return aliasRead(ctx, api, d)
}

func mappingRead(ctx context.Context, api firewall.API, d *schema.ResourceData) diag.Diagnostics {
	name := d.Id()

	alias, err := api.GetAlias(ctx, name)
	if err != nil {
		if strings.Contains(err.Error(), "no such alias") {
			d.SetId("")
			return nil
		}

		return diag.FromErr(err)
	}

	aliasMap := map[string]interface{}{
		mkAliasComment: alias.Comment,
		mkAliasName:    alias.Name,
		mkAliasCIDR:    alias.CIDR,
	}

	for key, val := range aliasMap {
		err = d.Set(key, val)
		if err != nil {
			return diag.FromErr(err)
		}
	}

	return nil
}

func mappingUpdate(ctx context.Context, api firewall.API, d *schema.ResourceData) diag.Diagnostics {
	comment := d.Get(mkAliasComment).(string)
	cidr := d.Get(mkAliasCIDR).(string)
	newName := d.Get(mkAliasName).(string)
	previousName := d.Id()

	body := &firewall.AliasUpdateRequestBody{
		ReName:  newName,
		CIDR:    cidr,
		Comment: &comment,
	}

	err := api.UpdateAlias(ctx, previousName, body)
	if err != nil {
		return diag.FromErr(err)
	}

	d.SetId(newName)

	return aliasRead(ctx, api, d)
}

func mappingDelete(ctx context.Context, api firewall.API, d *schema.ResourceData) diag.Diagnostics {
	name := d.Id()

	err := api.DeleteAlias(ctx, name)
	if err != nil {
		if strings.Contains(err.Error(), "no such alias") {
			d.SetId("")
			return nil
		}

		return diag.FromErr(err)
	}

	d.SetId("")

	return nil
}
