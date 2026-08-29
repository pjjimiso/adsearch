from typing import TypedDict


class User(TypedDict):
    name: str
    wwid: str
    bluebadge: bool


class AGSEntitlement(TypedDict): 
    name: str
    ad_obj: str
    users:  list[User]


def wwid_command(wwid: str) -> None:
    """
    Search for a user by WWID.

    Args:
        wworld_id (str): The WWID of the user to search for.
    """
    # Placeholder for the actual search logic
    print(f"Executing search for WWID: {wwid}")
