#include <net/if.h>
#include <stdio.h>

int main (void)
{
    struct if_nameindex *if_nidxs, *intf;

    if_nidxs = if_nameindex();
    if ( if_nidxs != NULL )
    {
        for (intf = if_nidxs; intf->if_index != 0 || intf->if_name != NULL; intf++)
        {
            printf("%s\n", intf->if_name);
        }

        if_freenameindex(if_nidxs);
    }

    return 0;
}