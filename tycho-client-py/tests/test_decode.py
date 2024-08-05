import json

from tycho_client.dto import (
    FeedMessage,
    SynchronizerState,
    SynchronizerStateEnum,
    Header,
)


def test_decode_snapshot(asset_dir):
    with (asset_dir / "snapshot.json").open("r") as fp:
        data = json.load(fp)

    msg = FeedMessage(**data)

    assert msg.sync_states["uniswap_v2"] == SynchronizerState(
        status=SynchronizerStateEnum.ready,
        header=Header(
            number=20440688,
            hash="0xc30593d774626d6175394d7d33c74bd40e7ddd2d2891eab0cc54032eafe15b98",
            parent_hash="0x954db41ab1ef9c32457b52c170d83f71f82a065ba0b4eeda8efb2da4b9e18162",
            revert=False,
        ),
    )


def test_decode_deltas(asset_dir):
    with (asset_dir / "deltas.json").open("r") as fp:
        data = json.load(fp)

    msg = FeedMessage(**data)

    assert msg.sync_states["uniswap_v2"] == SynchronizerState(
        status=SynchronizerStateEnum.ready,
        header=Header(
            number=20440962,
            hash="0x00d378b96546bc5ec4c64e225d2bb716867fd837d309bc79c5db321ecb1357ae",
            parent_hash="0x05d53b6b3b127ae642c409aeda425de3e5e3e444109d26cc54ca740be9a60316",
            revert=False,
        ),
    )
